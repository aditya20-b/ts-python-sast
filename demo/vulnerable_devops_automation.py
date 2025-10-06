#!/usr/bin/env python3
"""
Vulnerable DevOps Automation Script
This demonstrates security issues commonly found in DevOps automation,
CI/CD pipelines, deployment scripts, and infrastructure management tools.
"""

import os
import sys
import json
import yaml
import subprocess
import requests
import hashlib
import pickle
import tempfile
import shutil
from pathlib import Path
import logging
import time
from datetime import datetime

# PY.SECRET.HARDCODED - DevOps credentials and secrets
class DevOpsConfig:
    """Configuration with hardcoded secrets typical in DevOps environments"""

    def __init__(self):
        # Cloud provider credentials
        self.aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"  # SECURITY ISSUE: Hardcoded AWS credentials
        self.aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # SECURITY ISSUE: AWS secret
        self.azure_client_secret = "8Q~3Q~abcdefghijklmnopqrstuvwxyz1234567890"  # SECURITY ISSUE: Azure secret
        self.gcp_service_account_key = "/path/to/service-account-key.json"  # SECURITY ISSUE: Hardcoded path

        # Container registry credentials
        self.docker_registry_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # SECURITY ISSUE: GitHub token
        self.harbor_password = "Harbor12345!"  # SECURITY ISSUE: Harbor registry password

        # Database and messaging credentials
        self.postgres_connection = "postgresql://postgres:admin123@db.company.com:5432/production"  # SECURITY ISSUE: DB URL
        self.redis_password = "redis_prod_password_2023"  # SECURITY ISSUE: Redis password
        self.rabbitmq_credentials = "admin:rabbitmq_secret_2023"  # SECURITY ISSUE: RabbitMQ credentials

        # API keys and tokens
        # self.slack_webhook_url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"  # SECURITY ISSUE: Slack webhook
        self.github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"  # SECURITY ISSUE: GitHub token
        self.jenkins_api_token = "jenkins_token_1234567890abcdef"  # SECURITY ISSUE: Jenkins token

        # Encryption and signing keys
        self.jwt_secret_key = "super_secret_jwt_key_for_production"  # SECURITY ISSUE: JWT secret
        self.tls_private_key_password = "tls_key_password_2023"  # SECURITY ISSUE: TLS key password
        self.gpg_passphrase = "my_gpg_passphrase_12345"  # SECURITY ISSUE: GPG passphrase

config = DevOpsConfig()

class VulnerableDeploymentManager:
    """Deployment manager with security vulnerabilities"""

    def __init__(self):
        self.deployment_dir = "/tmp/deployments"
        self.artifact_cache = "/tmp/artifacts"
        self.logs_dir = "/var/log/deployments"

    def download_artifact(self, artifact_url, verify_ssl=False):
        """Download deployment artifact with SSL issues"""
        headers = {
            'Authorization': f'Bearer {config.github_token}',
            'User-Agent': 'DeploymentManager/1.0'
        }

        try:
            # PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
            response = requests.get(artifact_url, headers=headers, verify=verify_ssl)  # SECURITY ISSUE: verify=False
            return response.content
        except Exception as e:
            logging.error(f"Artifact download failed: {e}")
            return None

    def extract_deployment_package(self, package_path, destination):
        """Extract deployment package using shell commands"""
        package_name = Path(package_path).name

        # PY.SUBPROCESS.SHELL - Command injection via package extraction
        if package_name.endswith('.tar.gz'):
            cmd = f"tar -xzf {package_path} -C {destination} --strip-components=1"
            subprocess.run(cmd, shell=True)  # SECURITY ISSUE: shell=True with file path

        elif package_name.endswith('.zip'):
            cmd = f"unzip -o {package_path} -d {destination}"
            subprocess.run(cmd, shell=True)  # SECURITY ISSUE: shell=True with file path

        elif package_name.endswith('.deb'):
            # PY.OS.SYSTEM - Package installation via os.system
            os.system(f"dpkg -x {package_path} {destination}")  # SECURITY ISSUE: os.system with paths

    def deploy_to_kubernetes(self, manifest_path, namespace):
        """Deploy to Kubernetes with command injection"""
        # Load and process Kubernetes manifest
        with open(manifest_path, 'r') as f:
            manifest_content = f.read()

        # Replace placeholders with environment-specific values
        processed_manifest = manifest_content.replace('${NAMESPACE}', namespace)
        processed_manifest = processed_manifest.replace('${DB_PASSWORD}', config.postgres_connection.split(':')[2].split('@')[0])

        # Write processed manifest
        temp_manifest = f"/tmp/k8s_manifest_{namespace}.yaml"
        with open(temp_manifest, 'w') as f:
            f.write(processed_manifest)

        # PY.SUBPROCESS.SHELL - kubectl command with user input
        kubectl_cmd = f"kubectl apply -f {temp_manifest} -n {namespace}"
        try:
            result = subprocess.run(kubectl_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True with namespace
            return result.returncode == 0
        except Exception as e:
            logging.error(f"Kubernetes deployment failed: {e}")
            return False

    def update_load_balancer_config(self, lb_type, backend_servers):
        """Update load balancer configuration"""
        if lb_type == "nginx":
            # PY.SUBPROCESS.SHELL - nginx configuration update
            upstream_config = "\\n".join([f"server {server};" for server in backend_servers])
            nginx_cmd = f"echo 'upstream backend {{ {upstream_config} }}' > /etc/nginx/conf.d/upstream.conf && nginx -s reload"
            subprocess.run(nginx_cmd, shell=True)  # SECURITY ISSUE: shell=True with server list

        elif lb_type == "haproxy":
            # PY.OS.SYSTEM - HAProxy configuration update
            haproxy_config = "\\n".join([f"    server srv{i} {server} check" for i, server in enumerate(backend_servers)])
            os.system(f"echo 'backend webservers\\n{haproxy_config}' >> /etc/haproxy/haproxy.cfg && systemctl reload haproxy")  # SECURITY ISSUE: os.system

    def execute_deployment_script(self, script_path, environment):
        """Execute custom deployment script"""
        # Set environment variables
        deploy_env = os.environ.copy()
        deploy_env.update({
            'DEPLOY_ENV': environment,
            'AWS_ACCESS_KEY_ID': config.aws_access_key_id,  # SECURITY ISSUE: Exposing secrets in environment
            'AWS_SECRET_ACCESS_KEY': config.aws_secret_access_key,
            'DB_PASSWORD': config.postgres_connection.split(':')[2].split('@')[0],
            'REDIS_PASSWORD': config.redis_password
        })

        # PY.SUBPROCESS.SHELL - Script execution with environment variables
        script_cmd = f"bash {script_path} --env {environment}"
        try:
            result = subprocess.run(script_cmd, shell=True, env=deploy_env, capture_output=True, text=True)  # SECURITY ISSUE: shell=True
            return result.returncode == 0, result.stdout, result.stderr
        except Exception as e:
            logging.error(f"Deployment script execution failed: {e}")
            return False, "", str(e)

class VulnerableInfrastructureManager:
    """Infrastructure management with security issues"""

    def __init__(self):
        self.terraform_dir = "/tmp/terraform"
        self.ansible_dir = "/tmp/ansible"

    def generate_terraform_config(self, config_template, variables):
        """Generate Terraform configuration with template injection"""
        # PY.EVAL.USE - Template processing with eval
        processed_config = config_template
        for key, value in variables.items():
            # SECURITY ISSUE: eval for template variable substitution
            placeholder = f"${{{key}}}"
            if placeholder in processed_config:
                processed_config = processed_config.replace(placeholder, str(eval(value)))

        return processed_config

    def apply_terraform_changes(self, config_dir):
        """Apply Terraform configuration"""
        # Initialize Terraform
        # PY.SUBPROCESS.SHELL - Terraform commands
        init_cmd = f"cd {config_dir} && terraform init"
        subprocess.run(init_cmd, shell=True)  # SECURITY ISSUE: shell=True with directory

        # Plan changes
        plan_cmd = f"cd {config_dir} && terraform plan -out=tfplan"
        subprocess.run(plan_cmd, shell=True)  # SECURITY ISSUE: shell=True

        # Apply changes
        apply_cmd = f"cd {config_dir} && terraform apply -auto-approve tfplan"
        result = subprocess.run(apply_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True

        return result.returncode == 0

    def run_ansible_playbook(self, playbook_path, inventory, extra_vars):
        """Run Ansible playbook with command injection"""
        # Build extra vars string
        vars_str = " ".join([f"-e {key}={value}" for key, value in extra_vars.items()])

        # PY.SUBPROCESS.SHELL - Ansible command with user variables
        ansible_cmd = f"ansible-playbook -i {inventory} {playbook_path} {vars_str}"
        try:
            result = subprocess.run(ansible_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True with variables
            return result.returncode == 0, result.stdout
        except Exception as e:
            logging.error(f"Ansible playbook execution failed: {e}")
            return False, str(e)

    def provision_cloud_resources(self, cloud_provider, resource_config):
        """Provision cloud resources using CLI tools"""
        if cloud_provider == "aws":
            # PY.SUBPROCESS.SHELL - AWS CLI with hardcoded credentials
            aws_cmd = f"AWS_ACCESS_KEY_ID={config.aws_access_key_id} AWS_SECRET_ACCESS_KEY={config.aws_secret_access_key} aws ec2 run-instances"
            aws_cmd += f" --image-id {resource_config['ami_id']} --instance-type {resource_config['instance_type']}"
            subprocess.run(aws_cmd, shell=True)  # SECURITY ISSUE: Credentials in command line

        elif cloud_provider == "gcp":
            # PY.OS.SYSTEM - GCP CLI with service account
            gcloud_cmd = f"gcloud auth activate-service-account --key-file={config.gcp_service_account_key}"
            os.system(gcloud_cmd)  # SECURITY ISSUE: os.system with key file path

            create_cmd = f"gcloud compute instances create {resource_config['name']} --zone={resource_config['zone']}"
            os.system(create_cmd)  # SECURITY ISSUE: os.system with user input

class VulnerableMonitoringManager:
    """Monitoring and alerting with security issues"""

    def __init__(self):
        self.metrics_cache = "/tmp/metrics"
        self.alerts_config = "/tmp/alerts"

    def collect_system_metrics(self, target_hosts, metric_commands):
        """Collect metrics from remote hosts"""
        metrics_data = {}

        for host in target_hosts:
            host_metrics = {}
            for metric_name, command in metric_commands.items():
                # PY.SUBPROCESS.SHELL - Remote command execution
                ssh_cmd = f"ssh -o StrictHostKeyChecking=no {host} '{command}'"
                try:
                    result = subprocess.run(ssh_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True with SSH
                    host_metrics[metric_name] = result.stdout.strip()
                except Exception as e:
                    host_metrics[metric_name] = f"Error: {e}"

            metrics_data[host] = host_metrics

        return metrics_data

    def process_alert_rules(self, rules_config):
        """Process alert rules from configuration"""
        if isinstance(rules_config, str):
            # PY.YAML.UNSAFE_LOAD - Unsafe YAML processing
            rules = yaml.load(rules_config)  # SECURITY ISSUE: yaml.load with user input
        else:
            rules = rules_config

        processed_rules = []
        for rule in rules.get('alerts', []):
            # PY.EVAL.USE - Alert condition evaluation
            condition = rule.get('condition', 'False')
            try:
                # SECURITY ISSUE: eval of alert conditions
                rule['compiled_condition'] = compile(condition, '<alert_rule>', 'eval')
                processed_rules.append(rule)
            except Exception as e:
                logging.error(f"Failed to compile alert rule: {e}")

        return processed_rules

    def send_alert_notification(self, alert_message, notification_type):
        """Send alert notifications"""
        if notification_type == "slack":
            # PY.REQUESTS.VERIFY_FALSE - Slack webhook without SSL verification
            payload = {"text": alert_message}
            try:
                response = requests.post(config.slack_webhook_url, json=payload, verify=False)  # SECURITY ISSUE: verify=False
                return response.status_code == 200
            except Exception as e:
                logging.error(f"Slack notification failed: {e}")
                return False

        elif notification_type == "email":
            # PY.SUBPROCESS.SHELL - Email sending via sendmail
            email_cmd = f"echo '{alert_message}' | mail -s 'Alert Notification' admin@company.com"
            try:
                subprocess.run(email_cmd, shell=True)  # SECURITY ISSUE: shell=True with message content
                return True
            except Exception as e:
                logging.error(f"Email notification failed: {e}")
                return False

    def generate_metrics_hash(self, metrics_data):
        """Generate hash for metrics integrity"""
        metrics_str = json.dumps(metrics_data, sort_keys=True)
        # PY.HASH.WEAK - Using MD5 for metrics integrity
        return hashlib.md5(metrics_str.encode()).hexdigest()  # SECURITY ISSUE: MD5 is weak

class VulnerableConfigManager:
    """Configuration management with security vulnerabilities"""

    def __init__(self):
        self.config_cache = {}
        self.config_dir = "/tmp/configs"

    def load_configuration(self, config_source):
        """Load configuration from various sources"""
        if config_source.endswith('.pkl'):
            # PY.PICKLE.LOAD - Unsafe pickle deserialization
            with open(config_source, 'rb') as f:
                config_data = pickle.load(f)  # SECURITY ISSUE: pickle.load

        elif config_source.endswith('.yaml') or config_source.endswith('.yml'):
            # PY.YAML.UNSAFE_LOAD - Unsafe YAML loading
            with open(config_source, 'r') as f:
                config_data = yaml.load(f)  # SECURITY ISSUE: yaml.load

        elif config_source.startswith('http'):
            # PY.REQUESTS.VERIFY_FALSE - Remote config without SSL verification
            response = requests.get(config_source, verify=False)  # SECURITY ISSUE: verify=False
            config_data = response.json()

        else:
            with open(config_source, 'r') as f:
                config_data = json.load(f)

        return config_data

    def template_configuration(self, template_content, variables):
        """Process configuration templates"""
        processed_content = template_content

        # PY.EVAL.USE - Template variable substitution with eval
        for key, value in variables.items():
            placeholder = f"${{{key}}}"
            if placeholder in processed_content:
                try:
                    # SECURITY ISSUE: eval for template processing
                    evaluated_value = eval(str(value))
                    processed_content = processed_content.replace(placeholder, str(evaluated_value))
                except:
                    processed_content = processed_content.replace(placeholder, str(value))

        return processed_content

    def sync_configuration(self, source_path, destination_hosts):
        """Sync configuration to multiple hosts"""
        for host in destination_hosts:
            # PY.SUBPROCESS.SHELL - rsync with SSH
            sync_cmd = f"rsync -avz --delete {source_path}/ {host}:/opt/app/config/"
            try:
                subprocess.run(sync_cmd, shell=True, check=True)  # SECURITY ISSUE: shell=True with host

                # Restart services on remote host
                restart_cmd = f"ssh {host} 'systemctl restart application'"
                subprocess.run(restart_cmd, shell=True)  # SECURITY ISSUE: shell=True with SSH

            except Exception as e:
                logging.error(f"Configuration sync to {host} failed: {e}")

def main():
    """Main DevOps automation workflow"""
    # PY.SECRET.HARDCODED - Additional hardcoded secrets
    AUTOMATION_CONFIG = {
        'jenkins_url': 'https://jenkins.company.com',
        'jenkins_token': 'jenkins_api_token_123456789',  # SECURITY ISSUE: Hardcoded token
        'vault_token': 'hvs.CAESIJ8qp_xxxxxxxxxxxxxxxxxxxxxxxg',  # SECURITY ISSUE: Vault token
        'consul_token': 'consul_acl_token_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'  # SECURITY ISSUE: Consul token
    }

    if len(sys.argv) < 2:
        print("Usage: python vulnerable_devops_automation.py <operation> [args...]")
        print("Operations: deploy, provision, monitor, config-sync")
        sys.exit(1)

    operation = sys.argv[1]

    if operation == "deploy":
        if len(sys.argv) < 4:
            print("Usage: deploy <manifest_path> <namespace>")
            sys.exit(1)

        manifest_path = sys.argv[2]
        namespace = sys.argv[3]

        deployer = VulnerableDeploymentManager()
        success = deployer.deploy_to_kubernetes(manifest_path, namespace)
        print(f"Deployment {'succeeded' if success else 'failed'}")

    elif operation == "provision":
        if len(sys.argv) < 4:
            print("Usage: provision <cloud_provider> <config_json>")
            sys.exit(1)

        cloud_provider = sys.argv[2]
        # PY.EVAL.USE - Command line argument evaluation
        config_data = eval(sys.argv[3])  # SECURITY ISSUE: eval of command line argument

        infra_manager = VulnerableInfrastructureManager()
        infra_manager.provision_cloud_resources(cloud_provider, config_data)
        print("Provisioning initiated")

    elif operation == "monitor":
        if len(sys.argv) < 4:
            print("Usage: monitor <hosts_json> <commands_json>")
            sys.exit(1)

        # PY.EVAL.USE - Command line parsing with eval
        hosts = eval(sys.argv[2])  # SECURITY ISSUE: eval of hosts list
        commands = eval(sys.argv[3])  # SECURITY ISSUE: eval of commands dict

        monitoring = VulnerableMonitoringManager()
        metrics = monitoring.collect_system_metrics(hosts, commands)
        print(f"Collected metrics: {json.dumps(metrics, indent=2)}")

    elif operation == "config-sync":
        if len(sys.argv) < 4:
            print("Usage: config-sync <source_path> <hosts_json>")
            sys.exit(1)

        source_path = sys.argv[2]
        # PY.EVAL.USE - Host list evaluation
        hosts = eval(sys.argv[3])  # SECURITY ISSUE: eval of hosts list

        config_mgr = VulnerableConfigManager()
        config_mgr.sync_configuration(source_path, hosts)
        print("Configuration sync completed")

    else:
        print(f"Unknown operation: {operation}")
        sys.exit(1)

if __name__ == '__main__':
    # Configure logging
    log_level = os.environ.get('LOG_LEVEL', 'INFO')
    log_file = os.environ.get('LOG_FILE', '/tmp/devops_automation.log')  # SECURITY ISSUE: User-controllable log path

    logging.basicConfig(
        level=getattr(logging, log_level),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        filename=log_file
    )

    main()