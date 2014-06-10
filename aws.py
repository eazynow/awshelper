import boto
import boto.ec2
import boto.ec2.elb
from datetime import datetime
import json
import time
from boto.ec2.elb import HealthCheck
from boto.exception import BotoServerError


class Loggable(object):

    def __init__(self, debug):
        self.debug = debug

    def __log__(self, msg):
        if(self.debug):
            print("%s> %s" % (str(datetime.now()), msg))


class ElbComponent(Loggable):
    def __init__(self, elb, project_name, debug=False):
        super(ElbComponent, self).__init__(debug)
        self.elb = elb
        self.project_name = project_name


class Ec2Component(Loggable):

    def __init__(self, ec2, project_name, debug=False):
        super(Ec2Component, self).__init__(debug)
        self.ec2 = ec2
        self.project_name = project_name


class SecurityGroups(Ec2Component):
    """
    handles security group based interactions
    """

    filt_desc = "-sg-"

    @staticmethod
    def __get_rule_status__(rule):
        grants = ", ".join(map(lambda x: str(x), rule.grants))
        return "%s [%s>%s] %s" % (
            grants, rule.from_port, rule.to_port, rule.ip_protocol)

    @staticmethod
    def __get_status__(sg):
        resp = {}

        resp["id"] = sg.id
        resp["name"] = sg.name
        resp["description"] = sg.description
        resp["region"] = sg.region.name
        resp["instances"] = len(sg.instances())
        resp["rules"] = map(
            lambda x: SecurityGroups.__get_rule_status__(x),
            sg.rules)

        return resp

    @staticmethod
    def __get_name__(project_name, environment):
        return "%s%s%s" % (project_name, SecurityGroups.filt_desc, environment)

    @staticmethod
    def __get_description__(project_name, environment):
        return "%s server security group (%s)" % (project_name, environment)

    def get(self, environment=None):
        filt = self.project_name + SecurityGroups.filt_desc
        filt += environment if environment else "*"

        return self.ec2.get_all_security_groups(
            filters={"group-name": filt})

    def get_status(self, environment=None):
        return map(
            lambda x: SecurityGroups.__get_status__(x),
            self.get(environment))

    def create(self, environment, ports=[21, 22, 80, 9999, 9008],
               ports_local=[], ports_elb=[]):
        """
        create the aws security group for servers with relevant ports open
        """

        sg = self.ec2.create_security_group(
            SecurityGroups.__get_name__(self.project_name, environment),
            SecurityGroups.__get_description__(self.project_name, environment))
        map(
            lambda x: sg.authorize('tcp', x, x, '0.0.0.0/0'),
            ports)

        map(
            lambda x: sg.authorize('tcp', x, x, '127.0.0.1/0'),
            ports_local)

        # TODO: Set this up to work as it doesn't right now
        #map(
        #    lambda x: sg.authorize('tcp', x, x, 'amazon-elb/amazon-elb-sg'),
        #    ports_elb)

        return sg


class LoadBalancers(ElbComponent):
    """
    handles load balancer based interactions
    """

    lb_defaults = {}
    lb_defaults["interval"] = 6
    lb_defaults["healthy_threshold"] = 2
    lb_defaults["unhealthy_threshold"] = 2
    lb_defaults["target"] = 'HTTP:9008/login'

    @staticmethod
    def __get_status__(lb):
        if lb:
            resp = {}
            resp["name"] = lb.name
            resp["dns_name"] = lb.dns_name
            resp["instances"] = map(lambda x: x.id, lb.instances)
            resp["listeners"] = map(
                lambda x: LoadBalancers.__get_listener_status__(x),
                lb.listeners)
            return resp
        else:
            return "no load balancer found"

    @staticmethod
    def __get_listener_status__(listener):

        resp = "%s [%s>%s] %s" % (
            listener.protocol,
            listener.load_balancer_port,
            listener.instance_port,
            listener.InstanceProtocol)

        if listener.ssl_certificate_id:
            resp += " (sslcert:%s)" % listener.ssl_certificate_id

        return resp

    @staticmethod
    def __get_default_healthcheck__():
        return HealthCheck(
            interval = LoadBalancers.lb_defaults["interval"],
            healthy_threshold = LoadBalancers.lb_defaults["healthy_threshold"],
            unhealthy_threshold = LoadBalancers.lb_defaults["unhealthy_threshold"],
            target = LoadBalancers.lb_defaults["target"]
        )

    @staticmethod
    def __get_default_zones__():
        return ['us-east-1a', 'us-east-1b']

    @staticmethod
    def __get_name__(project_name, environment):
        return "%s-%s" % (project_name, environment)

    def get(self, environment):
        lbname = LoadBalancers.__get_name__(self.project_name, environment)
        try:
            elbs = self.elb.get_all_load_balancers(load_balancer_names=[lbname])
            if len(elbs) > 1:
                self.__log__("WARNING - expected 1 load balancer but found %d" % len(elbs))
            return elbs.pop()

        except BotoServerError as detail:
            if(detail.error_code == 'LoadBalancerNotFound'):
                self.__log__("Could not find a load balancer called %s" % lbname)
                return None
            else:
                self.__log__("Unexpected error: %s" % detail.error_message)

    def get_all(self):
        return self.elb.get_all_load_balancers()

    def get_status(self, environment):
        return LoadBalancers.__get_status__(self.get(environment))

    def delete(self, environment):
        lb = self.get(environment)
        if lb:
            self.elb.delete_load_balancer(lb.name)

    def register_instances(self, environment, instance_ids):
        lbname = LoadBalancers.__get_name__(self.project_name, environment)
        return self.elb.register_instances(lbname, instance_ids)

    def deregister_instances(self, environment, instance_ids):
        lbname = LoadBalancers.__get_name__(self.project_name, environment)
        return self.elb.deregister_instances(lbname, instance_ids)

    def create(self, environment, ports=[(80, 9999, 'http')], zones=[], healthcheck=None):
        if zones == []:
            self.__log__("no zones defined, so using default")
            zones = LoadBalancers.__get_default_zones__()

        if healthcheck is None:
            self.__log__("no healthcheck defined, so using default")
            healthcheck = LoadBalancers.__get_default_healthcheck__()

        lbname = LoadBalancers.__get_name__(self.project_name, environment)
        print "creating load balancer..."
        lb = self.elb.create_load_balancer(lbname, zones, ports)
        print "configuring load balancer healthcheck..."
        lb.configure_health_check(healthcheck)
        print "done."
        return lb


class Instances(Ec2Component):
    """
    handles instance based interactions
    """

    @staticmethod
    def __get_name__(project_name, environment):
        return "%s-%s play server" % (project_name, environment)

    @staticmethod
    def __instance_status__(instance):
        resp = {}
        resp["id"] = instance.id
        resp["name"] = instance.tags["Name"]
        resp["dns_name"] = instance.public_dns_name
        resp["state"] = instance.state
        resp["type"] = instance.instance_type
        resp["image"] = instance.image_id
        resp["key"] = instance.key_name

        return resp

    def get(self, environment=None, state=None):
        filters = {}
        filters["tag:" + AwsHelper.tags["project"]] = self.project_name
        if(environment):
            filters["tag:" + AwsHelper.tags["environment"]] = environment
        if state:
            filters["instance-state-name"] = state

        reservations = self.ec2.get_all_instances(filters=filters)

        # need to get instances from reservations, and reduce into one list
        return reduce(
            lambda x, y: x + y,
            map(lambda x: x.instances, reservations),
            [])

    def get_dns_names(self, environment=None, state=None):
        return map(
            lambda x: x.public_dns_name,
            self.get(environment, state))

    def get_ids(self, environment=None, state=None):
        return map(
            lambda x: x.id,
            self.get(environment, state))

    def get_status(self, environment=None, state=None):
        return map(
            lambda x: Instances.__instance_status__(x),
            self.get(environment, state))

    def start(self, environment=None, state=None):
        self.ec2.start_instances(
            instance_ids=self.get_ids(environment, state))

    def stop(self, environment=None, state=None):
        self.ec2.stop_instances(
            instance_ids=self.get_ids(environment, state))

    def terminate(self, environment=None, state=None):
        self.ec2.terminate_instances(
            instance_ids=self.get_ids(environment, state))

    def create(self, environment, ami_image="ami-7539b41c", key_name="hibu_voice_key", instance_type="m1.small", zone=None):
        # ami-7539b41c = ubuntu 12.10 64bit
        reservation = self.ec2.run_instances(
            ami_image,
            key_name=key_name,
            instance_type=instance_type,
            security_groups=[SecurityGroups.__get_name__(self.project_name, environment)],
            placement=zone)

        # setup tags (name, env, project)

        instance = reservation.instances[0]
        istatus = instance.update()
        print("waiting for new instance to start...")
        while istatus == 'pending':
            time.sleep(10)
            print("waiting...")
            istatus = instance.update()

        if istatus == 'running':
            print("Instance running. Setting tags...")
            instance.add_tag("Name", Instances.__get_name__(self.project_name, environment))
            instance.add_tag("Environment", environment)
            instance.add_tag("Project", self.project_name)
            return instance
        else:
            print('Instance did not start running. status: ' + istatus)
            return None


class AwsHelper(Loggable):
    """
    provides an interface to hibu aws deployments
    """

    tags = {}
    tags["project"] = "Project"
    tags["environment"] = "Environment"

    @staticmethod
    def __print_json__(json_text):
        print json.dumps(json.loads(json_text), sort_keys=False, indent=2)

    def __init__(self, project_name, region="us-east-1", debug=False):
        super(AwsHelper, self).__init__(debug)
        self.project_name = project_name

        self.__log__("AwsHelper created. Project name [%s]" % project_name)

        self.connect(region)
        self.connect_elb(region)
        self.instances = Instances(self.ec2, self.project_name, self.debug)
        self.load_balancers = LoadBalancers(self.elb, self.project_name, self.debug)
        self.security_groups = SecurityGroups(self.ec2, self.project_name, self.debug)

    def connect(self, region):
        self.__log__("connecting to aws ec2 [%s]" % region)
        self.ec2 = boto.ec2.connect_to_region(region)

    def connect_elb(self, region):
        self.__log__("connecting to aws elb [%s]" % region)
        self.elb = boto.ec2.elb.connect_to_region(region)

    def stop_environment(self, environment):
        self.instances.stop(environment)
        # mysql
        # elb

    def start_environment(self, environment):
        self.instances.start_instances(environment)

    def destroy_environment(self, environment):
        self.instances.terminate(environment)
        # mysql
        # elb
        # sec group

    def status(self, environment):
        """
        Show a status of the current aws connection.
        This will list out all the current basic details
        """
        resp = {}

        resp["environment"] = environment
        resp["project_name"] = self.project_name
        resp["instances"] = self.instances.get_status(environment)
        resp["load_balancer"] = self.load_balancers.get_status(environment)
        resp["security_groups"] = self.security_groups.get_status(environment)

        # match up instances to load balancer
        if resp["load_balancer"] != "no load balancer found":
            for inst in resp["instances"]:
                if inst["id"] in resp["load_balancer"]["instances"]:
                    inst["on_load_balancer"] = True
                    resp["load_balancer"]["instances"].remove(inst["id"])
                else:
                    inst["on_load_balancer"] = False

            if len(resp["load_balancer"]["instances"]) > 0:
                resp["load_balancer"]["unknown_instances"] = resp["load_balancer"]["instances"]

            del resp["load_balancer"]["instances"]

        return resp

    def print_status(self, environment):
        AwsHelper.__print_json__(json.dumps(self.status(environment)))
    
