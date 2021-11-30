from os.path import exists
from configparser import ConfigParser

from CSIC.libs.osintchck import OSINTBlock
from CSIC.csi_block import update_block_list, remove_csi_ips


class TestCSICConfig:
    def test_config_exists(self):
        """Tests to make sure the config file exists."""
        config_path = 'config.cnf'
        test = exists(config_path)
        assert test is True

    def test_vt_api_key(self):
        """Tests for the presence of a Virus Total api key."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'vt' in config['API']

    def test_fsb_api_key(self):
        """Tests for the presence of a Hybrid Analysis API key."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'fsb' in config['API']

    def test_mail_server(self):
        """Tests for the presence of the mail server config element."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'server' in config['mail']

    def test_mail_sender(self):
        """Tests for the presence of the mail sender config element."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'sender' in config['mail']

    def test_mail_recipients(self):
        """Tests for the presence of the mail recipient config element."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'rcpts' in config['mail']


class TestOSIBlock:
    def test_config(self):
        """Tests config for the path element."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'path' in config['block']

    def test_et_list(self):
        """Tests retrieving the ET compromised host list."""
        ip_block = OSINTBlock()
        et_response = ip_block.get_et_ch()
        data = {'response': et_response, 'list': ip_block.et_ch}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_abusech_block_list(self):
        """Tests retrieving the SSL blocklist from abuse.ch"""
        ip_block = OSINTBlock()
        abuse_ch_response = ip_block.get_ssl_bl()
        data = {'response': abuse_ch_response, 'list': ip_block.ssl_bl}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_talos_list(self):
        """Tests retrieving the Talos block list from Cisco."""
        ip_block = OSINTBlock()
        talos_response = ip_block.get_talos_list()
        data = {'response': talos_response, 'list': ip_block.tbl}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_blde_list(self):
        """Tests retrieving the blocklist.de ban list."""
        ip_block = OSINTBlock()
        blocklist_de_response = ip_block.get_blde_list()
        data = {'response': blocklist_de_response, 'list': ip_block.bl_de}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_nt_ssh_bl(self):
        """Tests retrieving the SSH ban list from nothink.org."""
        ip_block = OSINTBlock()
        nothink_response = ip_block.get_nt_ssh_bl()
        data = {'response': nothink_response, 'list': ip_block.nt_ssh_bl}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_abuse_ip_bl(self):
        """Tests retrieving the black list from the Abuse IP DB."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        api = config['API']['aipdb']
        ip_block = OSINTBlock()
        abuseip_response = ip_block.get_adb_bl(api)
        data = {
            'response': abuseip_response,
            'list': ip_block.adb_bl
        }
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_block_list_update(self):
        """Tests updating the block list."""
        csi_ips = []
        block_path = 'test_block_list.txt'
        abl = 'abl_example_ips'
        # Updating block file.
        csi_file = open(abl, 'r', encoding='ascii')
        for line in csi_file:
            csi_ips.append(line.strip('\n'))
        csi_file.close()
        update_block_list(block_path, csi_ips)
        # Making sure block file is updated.
        abl_counter = 0
        updated_block = open(block_path, 'r', encoding='ascii')
        for line in updated_block:
            if '#ABL' in line:
                abl_counter += 1
        updated_block.close()
        assert abl_counter >= 20

    def test_csi_ip_remove(self):
        """Tests removing CSI IPs."""
        # Removing CSI IPs.
        block_path = 'test_block_list.txt'
        remove_csi_ips(block_path)
        # Chekcing to make sure that are no CSI IPs in the file.
        block_file = open(block_path, 'r', encoding='ascii')
        abl_counter = 0
        for line in block_file:
            if '#ABL' in line:
                abl_counter += 1
        block_file.close()
        assert abl_counter == 0
