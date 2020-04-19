from os.path import exists
from requests import get
from configparser import ConfigParser


class TestCSICConfig:
    def test_config_exists(self):
        """Tests to make sure the config file exists."""
        config_path = r'../example.conf'
        test = exists(config_path)
        assert test is True

    def test_vt_api_key(self):
        """Tests for the presence of a Virus Total api key."""
        config_path = r'../example.conf'
        config = ConfigParser()
        config.read(config_path)
        assert 'vt' in config['API']

    def test_fsb_api_key(self):
        """Tests for the presence of a Hybrid Analysis API key."""
        config_path = r'../example.conf'
        config = ConfigParser()
        config.read(config_path)
        assert 'fsb' in config['API']

    def test_mail_server(self):
        """Tests for the presence of the mail server config element."""
        config_path = r'../example.conf'
        config = ConfigParser()
        config.read(config_path)
        assert 'server' in config['mail']

    def test_mail_sender(self):
        """Tests for the presence of the mail sender config element."""
        config_path = r'../example.conf'
        config = ConfigParser()
        config.read(config_path)
        assert 'sender' in config['mail']

    def test_mail_recipients(self):
        """Tests for the presence of the mail recipient config element."""
        config_path = r'../example.conf'
        config = ConfigParser()
        config.read(config_path)
        assert 'rcpts' in config['mail']


class TestOSIBlock:
    def tets_config(self):
        """Tests config for the path element."""
         config_path = r'../example.conf'
        config = ConfigParser()
        config.read(config_path)
        assert 'path' in config['block']
        
    def test_et_list(self):
        """Tests retrieving the ET compromised host list."""
        url = (
            'https://rules.emergingthreats.net' +
            '/blockrules/compromised-ips.txt'
        )
        data = get(url).text
        _list = data.split('\n')
        assert len(_list) > 10

    def test_abusech_block_list(self):
        """Tests retrieving the SSL blocklist from abuse.ch"""
        url = 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt'
        data = get(url).text
        _list = data.split('\n')
        assert len(_list) > 10

    def test_talos_list(self):
        """Tests retrieving the Talos block list from Cisco."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        data = get(url).text
        _list = data.split('\n')
        assert len(_list) > 10

    def test_blde_list(self):
        """Tests retrieving the blocklist.de ban list."""
        url = 'https://lists.blocklist.de/lists/all.txt'
        data = get(url).text
        _list = data.split('\n')
        assert len(_list) > 10

    def test_nt_ssh_bl(self):
        """Tests retrieving the SSH ban list from nothink.org."""
        url = (
            r'http://www.nothink.org/honeypots/' +
            r'honeypot_ssh_blacklist_2019.txt'
        )
        data = get(url).text
        _list = data.split('\n')
        assert len(_list) > 10
