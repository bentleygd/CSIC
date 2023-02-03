from os.path import exists
from configparser import ConfigParser

import libs.osintchck as osintchck
from csi_block import update_block_list, remove_csi_ips


class Test_CSIC_Config:
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
        assert len(config['API']['vt']) == 64

    def test_fsb_api_key(self):
        """Tests for the presence of a Hybrid Analysis API key."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'fsb' in config['API']
        assert len(config['API']['fsb']) == 64

    def test_abuse_db_api_key(self):
        """Tests for the presence of an Abuse DB API key."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'aipdb' in config['API']
        assert len(config['API']['aipdb']) == 80

    def test_otx_api_key(self):
        """Tests for the presence of an AlienVault OTX API key."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'otx' in config['API']
        assert len(config['API']['otx']) == 64

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


class Test_Domain_OSINT:
    def test_virus_total(self):
        """Tests VirusTotal checks for a domain name"""
        config = ConfigParser()
        config.read('config.cnf')
        vt_api = config['API']['vt']
        domain_osint = osintchck.DomainOSINT('example.com')
        vt_response = domain_osint.VTChck(vt_api)
        assert vt_response == 200

    def test_falcon_sandbox(self):
        """Tests Falcon Sandbox checks for a domain name"""
        config = ConfigParser()
        config.read('config.cnf')
        fsb_api = config['API']['fsb']
        domain_osint = osintchck.DomainOSINT('example.com')
        fsb_response = domain_osint.FSBChck(fsb_api)
        assert fsb_response == 200

    def test_urlhaus(self):
        """Tests checking URLHaus for a domain"""
        domain_osint = osintchck.DomainOSINT('example.com')
        urlhaus = domain_osint.UHChck()
        assert urlhaus == 'no_results'

    def test_otx(self):
        """Tests checking AlienVault OTX"""
        config = ConfigParser()
        config.read('config.cnf')
        otx_api = config['API']['otx']
        domain_osint = osintchck.DomainOSINT('example.com')
        otx_check = domain_osint.OTXCheck(otx_api)
        assert otx_check == 200


class Test_IP_Osint:
    def test_virus_total(self):
        """Tests VirusTotal checks for an IP address"""
        config = ConfigParser()
        config.read('config.cnf')
        vt_api = config['API']['vt']
        ip_osint = osintchck.IPOSINT('8.8.8.8')
        vt_response = ip_osint.VTChck(vt_api)
        assert vt_response == 200

    def test_falcon_sandbox(self):
        """Tests Falcon Sandbox checks for an IP address"""
        config = ConfigParser()
        config.read('config.cnf')
        fsb_api = config['API']['fsb']
        ip_osint = osintchck.IPOSINT('8.8.8.8')
        fsb_response = ip_osint.FSBChck(fsb_api)
        assert fsb_response == 200

    def test_talos_black_list(self):
        """Tests retrieving Cisco Talos black list."""
        ip_osint = osintchck.IPOSINT('8.8.8.8')
        talos_response = ip_osint.TBLChck()
        assert talos_response == 200
        assert ip_osint.tbl_status == 'Non-block listed IP'

    def test_urlhaus(self):
        """Tests checking URLHaus"""
        ip_osint = osintchck.IPOSINT('8.8.8.8')
        urlhaus = ip_osint.UHChck()
        assert urlhaus == 'no_results'

    def test_abuse_ip_db(self):
        """Tests checking the Abuse IP DB."""
        config = ConfigParser()
        config.read('config.cnf')
        abuse_api = config['API']['aipdb']
        ip_osint = osintchck.IPOSINT('8.8.8.8')
        abusedb_response = ip_osint.AIDBCheck(abuse_api)
        assert abusedb_response == 200

    def test_otx(self):
        """Tests checking AlienVault OTX"""
        config = ConfigParser()
        config.read('config.cnf')
        otx_api = config['API']['otx']
        ip_osint = osintchck.IPOSINT('8.8.8.8')
        otx_response = ip_osint.OTXCheck(otx_api)
        assert otx_response == 200


class Test_URL_OSINT:
    def test_virus_total(self):
        """Tests VirusTotal checks for a URL"""
        config = ConfigParser()
        config.read('config.cnf')
        vt_api = config['API']['vt']
        url_osint = osintchck.URLOSINT('http://www.example.com/')
        vt_response = url_osint.VTChck(vt_api)
        assert vt_response == 200

    def test_falcon_sandbox(self):
        """Tests Falcon Sandbox checks for a URL"""
        config = ConfigParser()
        config.read('config.cnf')
        fsb_api = config['API']['fsb']
        url_osint = osintchck.URLOSINT('http://www.example.com/')
        fsb_response = url_osint.FSBChck(fsb_api)
        assert fsb_response == 200

    def test_urlhaus(self):
        """Tests checking URLHaus for a URL"""
        url_osint = osintchck.URLOSINT('http://wwww.example.com/')
        urlhaus = url_osint.UHChck()
        assert urlhaus == 'no_results'

    def test_otx(self):
        """Tests checking AlienVault OTX"""
        config = ConfigParser()
        config.read('config.cnf')
        otx_api = config['API']['otx']
        url_osint = osintchck.URLOSINT('http://www.example.com/')
        otx_check = url_osint.OTXCheck(otx_api)
        assert otx_check == 200


class Test_File_OSINT:
    def test_virus_total(self):
        """Tests VirusTotal checks for a file"""
        config = ConfigParser()
        config.read('config.cnf')
        vt_api = config['API']['vt']
        bad_hash = '321ba6e02c0aef1ac2cf8281a04dbebc3053b86a'
        file_osint = osintchck.FileOSINT(bad_hash)
        vt_response = file_osint.VTChck(vt_api)
        assert vt_response == 200

    def test_falcon_sandbox(self):
        """Tests Falcon Sandbox checks for a file"""
        config = ConfigParser()
        config.read('config.cnf')
        fsb_api = config['API']['fsb']
        bad_hash = '321ba6e02c0aef1ac2cf8281a04dbebc3053b86a'
        file_osint = osintchck.FileOSINT(bad_hash)
        fsb_response = file_osint.FSBChck(fsb_api)
        assert fsb_response == 200

    def test_otx(self):
        """Tests checking AlienVault OTX"""
        config = ConfigParser()
        config.read('config.cnf')
        otx_api = config['API']['otx']
        bad_hash = '321ba6e02c0aef1ac2cf8281a04dbebc3053b86a'
        file_osint = osintchck.FileOSINT(bad_hash)
        otx_check = file_osint.OTXCheck(otx_api)
        assert otx_check == 200


class Test_OSI_Block:
    def test_config(self):
        """Tests config for the path element."""
        config_path = 'config.cnf'
        config = ConfigParser()
        config.read(config_path)
        assert 'path' in config['block']

    def test_et_list(self):
        """Tests retrieving the ET compromised host list."""
        ip_block = osintchck.OSINTBlock()
        et_response = ip_block.get_et_ch()
        data = {'response': et_response, 'list': ip_block.et_ch}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_abusech_block_list(self):
        """Tests retrieving the SSL blocklist from abuse.ch"""
        ip_block = osintchck.OSINTBlock()
        abuse_ch_response = ip_block.get_ssl_bl()
        data = {'response': abuse_ch_response, 'list': ip_block.ssl_bl}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_talos_list(self):
        """Tests retrieving the Talos block list from Cisco."""
        ip_block = osintchck.OSINTBlock()
        talos_response = ip_block.get_talos_list()
        data = {'response': talos_response, 'list': ip_block.tbl}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_blde_list(self):
        """Tests retrieving the blocklist.de ban list."""
        ip_block = osintchck.OSINTBlock()
        blocklist_de_response = ip_block.get_blde_list()
        data = {'response': blocklist_de_response, 'list': ip_block.bl_de}
        if data['response'] == 200 and len(data['list']) > 10:
            test = True
        assert test is True

    def test_nt_ssh_bl(self):
        """Tests retrieving the SSH ban list from nothink.org."""
        ip_block = osintchck.OSINTBlock()
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
        ip_block = osintchck.OSINTBlock()
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
