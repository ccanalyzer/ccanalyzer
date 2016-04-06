import os, re
import hashlib
import datetime
import ciscoconfparse as ccp

from . import apps
from . import utils

class Repository(object):
    @staticmethod
    def list(path):
        config_files = []
        for root, dirs, files in os.walk(path):
            for config_file in files:
                if config_file.endswith(apps.Config.repo_conf_extensions):
                    config_files.append(RepositoryFile(os.path.join(root, config_file), path))
        config_files.sort(key=lambda c:c.ctime, reverse=True)
        return config_files

    @staticmethod
    def find(path, query_regex):
        results = list()
        re_query_regex = re.compile(query_regex, re.IGNORECASE)
        for root, dirs, files in os.walk(path):
            for config_file in files:
                if config_file.endswith(apps.Config.repo_conf_extensions):
                    try:
                        matches = []
                        with open(os.path.join(root, config_file)) as f:
                            for line, text in enumerate(f):
                                if re_query_regex.search(text):
                                    matches.append({ 'line': line, 'text': text })
                        if matches: # swaggy stuff only if something is found...
                            results.append({
                                'file': RepositoryFile(os.path.join(root, config_file), path),
                                'file_matches': matches
                            })
                    except IOError:
                        pass

        results.sort(key=lambda c: c['file'].mtime, reverse=True)
        return results

    @staticmethod
    def load(path, name):
        file_path = os.path.join(path, name.replace('../', ''))
        if os.path.isfile(file_path):
            try:
                return RepositoryFile(file_path, path)
            except Exception as e: pass

        # let view handle a 404 condition
        return None

class RepositoryFile(object):
    """ an abstract object to summarize a config attributes on the repository """
    def __init__(self, file_path, root_path):
        self.path = file_path                                     # /var/www/vhosts/.../LABNET/R1.cfg
        self.name = self.path.replace('%s/' % root_path, '', 1)   # LABNET/R1.cfg
        self.size = os.path.getsize(file_path)                    # 1024
        self.hsize = utils.Filesystem.hsize_iec(self.size)   # 1KiB

        # use datetime as it's easier to format at render stage with t|date:'...'
        self.ctime = datetime.datetime.fromtimestamp(os.path.getctime(file_path))
        self.mtime = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))

    @property
    def contents(self):
        contents = str()
        try:
            contents = open(self.path).read()
        except IOError: pass
        return contents

    def to_json(self):
        return {
            'path': self.path, 'name': self.name,
            'size': self.size, 'hsize': self.hsize,
            'ctime': self.ctime.strftime('%Y-%m-%d %H:%M'),
            'mtime': self.mtime.strftime('%Y-%m-%d %H:%M')
        }

class Report(object):
    links_library = {
        'nsa_router_security_guide': {
            'name': 'NSA C4-040R-02',
            'href': 'https://www.nsa.gov/ia/_files/routers/c4-040r-02.pdf'
        },
        'cisco_password_management': {
            'name': 'Passwords and Privileges Commands',
            'href': 'http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/command/reference/fsecur_r/srfpass.html#wp1030793'
        },
        'cisco_password_encryption_facts': {
            'name': 'Password Encryption Facts',
            'href': 'http://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html'
        },
        'cisco_ssh_configuration': {
            'name': 'Configuring Secure Shell (SSH)',
            'href': 'http://www.cisco.com/c/en/us/td/docs/ios/12_2/security/configuration/guide/fsecur_c/scfssh.html'
        },
        'cisco_logging_configuration': {
            'name': 'Configuring System Message Logging',
            'href': 'http://www.cisco.com/c/en/us/td/docs/app_ntwk_services/data_center_app_services/ace_appliances/vA1_7_/configuration/system/message/guide/sysmsgd/config.html'
        },
        'cisco_snmp_server_configuration': {
            'name': 'SNMP Commands',
            'href': 'http://www.cisco.com/c/en/us/td/docs/ios/12_2/configfun/command/reference/ffun_r/frf014.html#wp1022436'
        },
        'cisco_ntp_server_configuration': {
            'name': 'Network Time Protocol',
            'href': 'http://www.cisco.com/c/en/us/support/docs/availability/high-availability/19643-ntpm.html'
        },
        'cisco_tacacsplus_radius_krbs_configuration': {
            'name': 'Configuring TACACS+, RADIUS',
            'href': 'http://www.cisco.com/c/en/us/support/docs/security-vpn/terminal-access-controller-access-control-system-tacacs-/13847-72.html'
        },
        'cisco_tty_vty_configuration': {
            'name': 'Physical and Virtual Terminals',
            'href': 'http://www.cisco.com/c/en/us/td/docs/routers/crs/software/crs_r4-2/system_management/configuration/guide/b_sysman_cg42crs/b_sysman_cg42crs_chapter_01011.html'
        }
    }

    """ the audit report, as generated by the logic stored in Audit.do_report() et al. """
    def __init__(self, path, name):
        self.config_path = path # e.g. '/srv/cvs/repository/rt-configs/R1.cfg'
        self.config_name = name # e.g. 'R1.cfg', unbound from the real path
        self.config_text = open(self.config_path).read() # e.g. "!\nhos..."
        self.config_hash = hashlib.sha1(self.config_text).hexdigest()

        # whether or not self.config_path came from a temporary (uploaded) file, or from the repository
        self.is_src_repo = True if not self.config_path.startswith('/tmp') else False

        # configuration analysis log entries, findings during the analysis
        self.log_entries = []

        # configuration parameters, attributes, entities, &c.
        self.device_hostname = str()                # e.g. 'gw-1-stgo1'
        self.device_accounts = []                   # e.g. [{'name': 'netadmin', 'type': 'password', 'hash': ...}, ...]
        self.device_ssh_conf = {}                   # e.g. { 'enabled': True, 'version': 2, ...}
        self.device_logging_hosts = []              # e.g. [ '1.2.3.4', '5.6.7.8', ...]
        self.device_snmp_server_communities = []    # e.g. [{'name': 'labnet', 'mode': 'RO' }, ...]
        self.device_ntp_server_conf  = {}           # e.g. { 'address': '1.2.3.4', 'version': 4 }
        self.device_radius_server_source_ports = {} # e.g. { 'start': 1234, 'end': 4321 }
        self.device_line_vty_ranges = []            # e.g. [{'vty_start': 0, 'vty_end': 4, ...}, ...]
        self.device_standard_acls = []              # e.g. [{'number':  64, 'action': 'permit', ...}, ...]
        self.device_extended_acls = []              # e.g. [{'number': 128, 'action': 'permit', ...}, ...]

    @property
    def are_all_local_passwd_encrypted(self):
        """ whether or not a 'password 7' thing is in the config """
        for account in self.device_accounts:
            try:
                if account['hash_type'] == 'password 7':
                    return False
            except KeyError:
                pass
        return True

    @property
    def are_all_line_vty_ranges_specific(self):
        """ whether or not there is a 'transport input all' in the line vty 0 N """
        for line_vty_range in self.device_line_vty_ranges:
            try:
                if 'all' in line_vty_range['transport_inputs']:
                    return False
            except KeyError:
                pass
        return True

class Audit(object):
    def __init__(self, path, name):
        self.path   = path                    # e.g. '/srv/cvs/repository/rt-configs/R1.cfg'
        self.report = Report(self.path, name) # e.g. Report('/srv/...nfigs/R1.cfg', 'R1.cfg')
        self._d_ccp = ccp.CiscoConfParse(self.path) # this is the parser intance (protected!)

    def __audit_hostname(self):
        """ validates that device uses a custome hostname """
        _regex_hostname = r'^hostname\s+([^\s]+)' # e.g. hostname R1
        hostname_entries = self._d_ccp.find_objects(_regex_hostname)
        if hostname_entries:
            hostname_entry_text = str()
            for hostname_entry in hostname_entries:
                self.report.device_hostname = re.match(_regex_hostname, hostname_entry.text, re.IGNORECASE).group(1)
                hostname_entry_text = hostname_entry.text

            self.report.log_entries.append({
                'severity': 'info',
                'message': 'The device uses a custom Hostname (%s)' % self.report.device_hostname,
                'links': [Report.links_library['nsa_router_security_guide']],
                'text': hostname_entry_text
            })
        else:
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device uses its default Hostname',
                'links': [Report.links_library['nsa_router_security_guide']]
            })

    def __audit_username(self):
        """ collects the accounts (secret and password) in local database """
        _regex_username = r'^username\s+([^\s]+)'  # username netadmin

        username_entries = self._d_ccp.find_objects(_regex_username)
        if username_entries:
            for username_entry in username_entries:
                name = re.match(_regex_username, username_entry.text, re.IGNORECASE).group(1)
                account = { 'name': name, 'text': username_entry.text } # save entire text line
                m = re.search('((?:password|secret)\s+[0-9]|password\s+encrypted)\s+([^\s]+)',
                              username_entry.text,
                              re.IGNORECASE)
                if m:
                    account['hash']      = m.group(2) # e.g. $1$1111$111111111111111111
                    account['hash_type'] = m.group(1) # e.g. secret 5, or password 7
                    if re.match('password\s+(encrypted|7)', account['hash_type'], re.IGNORECASE):
                        self.report.log_entries.append({
                            'severity': 'oops',
                            'message': 'The user %s is using a weak, reversible password' % account['name'],
                            'links': [Report.links_library['cisco_password_encryption_facts']],
                            'text': username_entry.text
                        })
                m = re.search('privilege\s+([0-9]+)', username_entry.text, re.IGNORECASE)
                if m:
                    account['privilege'] = m.group(1)

                self.report.device_accounts.append(account)
        else:
            self.report.log_entries.append({
                'severity': 'oops',
                'message': 'There is not a single local Account in the database',
                'links': [Report.links_library['cisco_password_management']]
            })

    def __audit_ip_ssh_version(self):
        """ validates the existence of a SSH daemon, oops against SSHv1 """
        _regex_ip_ssh_version = r'^ip\s+ssh\s+version\s+([1-2])\b'  # ip ssh version 2
        ip_ssh_version_entries = self._d_ccp.find_objects(_regex_ip_ssh_version)
        if ip_ssh_version_entries:
            self.report.device_ssh_conf['enabled'] = True
            for ip_ssh_version_entry in ip_ssh_version_entries:
                version = re.match(_regex_ip_ssh_version, ip_ssh_version_entry.text, re.IGNORECASE).group(1)
                self.report.device_ssh_conf['version'] = int(version)
                if int(version) == 1:
                    self.report.log_entries.append({
                        'severity': 'oops',
                        'message': 'The device uses the insecure SSHv1 Protocol for its Daemon',
                        'links': [Report.links_library['cisco_ssh_configuration']],
                        'text' : ip_ssh_version_entry.text
                    })
                else: # only notifiy if a warning hasn't been triggered yet
                    self.report.log_entries.append({
                        'severity': 'info',
                        'message': 'The device explicitly enables a SSH Daemon',
                        'links': [Report.links_library['cisco_ssh_configuration']],
                        'text': ip_ssh_version_entry.text
                    })
        else:
            self.report.device_ssh_conf['enabled'] = False
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device does not explicitly enable a SSH Daemon',
                'links': [Report.links_library['cisco_ssh_configuration']]
            })

    def __audit_logging_host(self):
        """ validates the existence of a configured central syslog server """
        _regex_logging_host = r'^logging\s+(?:host\s+)?([0-9\.]+)'  # logging a.b.c.d or logging host a.b.c.d
        logging_host_entries = self._d_ccp.find_objects(_regex_logging_host)
        if logging_host_entries:
            for logging_host_entry in logging_host_entries:
                address = re.match(_regex_logging_host, logging_host_entry.text, re.IGNORECASE).group(1)
                self.report.device_logging_hosts.append(address)
                self.report.log_entries.append({
                    'severity': 'info',
                    'message': 'Found a Centralized System Log Server (%s)' % address,
                    'links': [Report.links_library['cisco_logging_configuration']],
                    'text': logging_host_entry.text
                })
        else:
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device does not relay its syslog to a Centralized Server',
                'links': [Report.links_library['cisco_logging_configuration']]
            })

    def __audit_snmp_server_communities(self):
        """ validates the existence of a configured SNMP community string + perms """
        _regex_snmp_server_communities = r'^snmp-server\s+community\s+([^\s]+)'
        snmp_server_community_entries = self._d_ccp.find_objects(_regex_snmp_server_communities)
        if snmp_server_community_entries:
            for snmp_server_community_entry in snmp_server_community_entries:
                snmp_server_community = dict()
                snmp_server_community['name'] = re.match(_regex_snmp_server_communities,
                                                         snmp_server_community_entry.text,
                                                         re.IGNORECASE).group(1)
                self.report.log_entries.append({
                    'severity': 'info',
                    'message': 'The device joins to a SNMP community (%s)' % snmp_server_community['name'],
                    'links': [Report.links_library['cisco_snmp_server_configuration']],
                    'text': snmp_server_community_entry.text
                })

                m = re.search(r'\b(RO|RW)\b', snmp_server_community_entry.text, re.IGNORECASE)
                if m:
                    snmp_server_community['mode'] = m.group(1)
                    if 'RW' in snmp_server_community['mode']:
                        self.report.log_entries.append({
                            'severity': 'warn',
                            'message': 'SNMP community %s is accessed in RW mode' % snmp_server_community['name'],
                            'links': [Report.links_library['cisco_snmp_server_configuration']],
                            'text': snmp_server_community_entry.text
                        })

                self.report.device_snmp_server_communities.append(snmp_server_community)
        else:
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device does not join to any SNMP community',
                'links': [Report.links_library['cisco_snmp_server_configuration']]
            })

    def __audit_ntp_server(self):
        """ validates the existence of a configured central syslog server """
        _regex_ntp_server = r'^ntp\s+server\s+([^\s]+)'  # ntp server 1.2.3.4 or ntp server ntp.shoa.cl
        ntp_server_entries = self._d_ccp.find_objects(_regex_ntp_server)
        if ntp_server_entries:
            for ntp_server_entry in ntp_server_entries:
                address = re.match(_regex_ntp_server, ntp_server_entry.text, re.IGNORECASE).group(1)
                self.report.device_ntp_server_conf['address'] = address
                m = re.search('version\s+([1-4])', ntp_server_entry.text, re.IGNORECASE)
                if m:
                    self.report.device_ntp_server_conf['version'] = int(m.group(1))

                self.report.log_entries.append({
                    'severity': 'info',
                    'message': "The device is using an NTP server sync'd clock (%s)" % address,
                    'links': [Report.links_library['cisco_ntp_server_configuration']],
                    'text': ntp_server_entry.text
                })
        else:
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device may be using an outdated Clock as it lacks of an NTP server',
                'links': [Report.links_library['cisco_ntp_server_configuration']]
            })

    def __audit_radius_server_source_ports(self):
        """ collects the port range of RADIUS server """
        _regex_radius_server_source_ports = r'^radius-server\s+source-ports\s+([0-9]+)-([0-9]+)'
        radius_server_source_ports_entries = self._d_ccp.find_objects(_regex_radius_server_source_ports)
        if radius_server_source_ports_entries:
            for radius_server_source_ports_entry in radius_server_source_ports_entries:
                m = re.match(_regex_radius_server_source_ports, radius_server_source_ports_entry.text, re.IGNORECASE)
                self.report.device_radius_server_source_ports['start'] = int(m.group(1))
                self.report.device_radius_server_source_ports['end']   = int(m.group(2))

                self.report.log_entries.append({
                    'severity': 'info',
                    'message': 'The device explicitly specifies a RADIUS source-ports range (%d to %d)' % (
                        self.report.device_radius_server_source_ports['start'],
                        self.report.device_radius_server_source_ports['end']
                    ),
                    'links': [Report.links_library['cisco_tacacsplus_radius_krbs_configuration']],
                    'text': radius_server_source_ports_entry.text
                })
        else:
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device does not explicitly specifies a RADIUS source-ports range',
                'links': [Report.links_library['cisco_tacacsplus_radius_krbs_configuration']]
            })

    def __audit_line_vty_range(self):
        """ collects the line vty in ranges, and verifies no 'all' transport is set """
        _regex_line_vty_range = r'^line\s+vty\s+([0-9]+)\s+([0-9]+)' # line vty 0 4
        line_vty_range_entries = self._d_ccp.find_objects(_regex_line_vty_range)
        if line_vty_range_entries:
            for line_vty_range_entry in line_vty_range_entries:
                line_vty_range_start = int(re.match(_regex_line_vty_range, line_vty_range_entry.text, re.IGNORECASE).group(1))
                line_vty_range_end   = int(re.match(_regex_line_vty_range, line_vty_range_entry.text, re.IGNORECASE).group(2))
                line_vty_range = { 'vty_start': line_vty_range_start, 'vty_end': line_vty_range_end, 'text': line_vty_range_entry.text }
                for line_vty_transport_input in line_vty_range_entry.re_search_children('^\s*transport\s+input\s+'):
                    line_vty_range['transport_inputs'] = []
                    if 'all' in line_vty_transport_input.text:
                        line_vty_range['transport_inputs'].append('all')
                        self.report.log_entries.append({
                            'severity': 'oops',
                            'message': 'The device line vty %d %d uses transport input all; ergo, this may be insecure' % (
                                line_vty_range_start,
                                line_vty_range_end
                            ),
                            'links': [Report.links_library['cisco_tty_vty_configuration']],
                            'text': line_vty_transport_input.text
                        })

                    if not 'all' in line_vty_range['transport_inputs'] and 'telnet' in line_vty_transport_input.text:
                        line_vty_range['transport_inputs'].append('telnet')
                        self.report.log_entries.append({
                            'severity': 'info',
                            'message': 'The device line vty %d %d allows telnet, beware of plaintext passwords!' % (
                                line_vty_range_start,
                                line_vty_range_end
                            ),
                            'links': [Report.links_library['cisco_tty_vty_configuration']],
                            'text': line_vty_transport_input.text
                        })
                    if not 'all' in line_vty_range['transport_inputs'] and 'ssh' in line_vty_transport_input.text:
                        line_vty_range['transport_inputs'].append('ssh')
                        self.report.log_entries.append({
                            'severity': 'info',
                            'message': 'The device VTY lines %d-%d allow Secure Shell (SSH), this is expected!' % (
                                line_vty_range_start,
                                line_vty_range_end
                            ),
                            'links': [Report.links_library['cisco_tty_vty_configuration']],
                            'text': line_vty_transport_input.text
                        })
                self.report.device_line_vty_ranges.append(line_vty_range)
        else:
            self.report.log_entries.append({
                'severity': 'warn',
                'message': 'The device does not have any line VTY settings configured',
                'links': [Report.links_library['cisco_tty_vty_configuration']]
            })

    def __audit_access_list_standard(self):
        """ collects all standard ACLs (1-99, 1300-1999) """
        _regex_access_list_standard = r'^access-list\s+([0-9]{2}|1[3-9][0-9]{2})\s+(permit|deny)\s+'
        access_list_standard_entries = self._d_ccp.find_objects(_regex_access_list_standard)
        if access_list_standard_entries:
            for access_list_standard_entry in access_list_standard_entries:
                m = re.match(_regex_access_list_standard, access_list_standard_entry.text, re.IGNORECASE)
                acl = { 'number': int(m.group(1)), 'action': m.group(2), 'text': access_list_standard_entry.text }
                self.report.device_standard_acls.append(acl)

    def __audit_access_list_extended(self):
        """ collects all extendded ACLs (100-199, 2000-2699) """
        _regex_access_list_extended = r'^access-list\s+(1[0-9]{2}|2[0-6][0-9]{2})\s+(permit|deny)\s+'
        access_list_extended_entries = self._d_ccp.find_objects(_regex_access_list_extended)
        if access_list_extended_entries:
            for access_list_extended_entry in access_list_extended_entries:
                m = re.match(_regex_access_list_extended, access_list_extended_entry.text, re.IGNORECASE)
                acl = {'number': int(m.group(1)), 'action': m.group(2), 'text': access_list_extended_entry.text}
                self.report.device_extended_acls.append(acl)

    def _do_audit(self):
        self.__audit_hostname()
        self.__audit_username()
        self.__audit_ip_ssh_version()
        self.__audit_logging_host()
        self.__audit_snmp_server_communities()
        self.__audit_ntp_server()
        self.__audit_radius_server_source_ports()
        self.__audit_line_vty_range()
        self.__audit_access_list_standard()
        self.__audit_access_list_extended()

    def do_report(self):
        try:
            self._do_audit()
        except Exception as e:
            print e
            pass

        return self.report
