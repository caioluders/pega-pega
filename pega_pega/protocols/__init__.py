from .base import BaseProtocolHandler
from .http_handler import HttpHandler
from .https_handler import HttpsHandler
from .dns_handler import DnsHandler
from .ftp_handler import FtpHandler
from .smtp_handler import SmtpHandler
from .pop3_handler import Pop3Handler
from .imap_handler import ImapHandler
from .ssh_handler import SshHandler
from .telnet_handler import TelnetHandler
from .ldap_handler import LdapHandler
from .mysql_handler import MysqlHandler
from .raw_tcp_handler import RawTcpHandler
from .snmp_handler import SnmpHandler
from .syslog_handler import SyslogHandler

HANDLER_REGISTRY: dict[str, type[BaseProtocolHandler]] = {
    "http": HttpHandler,
    "https": HttpsHandler,
    "dns": DnsHandler,
    "ftp": FtpHandler,
    "smtp": SmtpHandler,
    "pop3": Pop3Handler,
    "imap": ImapHandler,
    "ssh": SshHandler,
    "telnet": TelnetHandler,
    "ldap": LdapHandler,
    "mysql": MysqlHandler,
    "raw_tcp": RawTcpHandler,
    "snmp": SnmpHandler,
    "syslog": SyslogHandler,
}
