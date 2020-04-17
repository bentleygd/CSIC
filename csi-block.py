from libs.osintchck import OSINTBlock


def main():
    """Doing the thing."""
    ip_block = OSINTBlock()
    # Retrieving the block lists.
    emerging_threat_response = ip_block.get_et_ch()
    if emerging_threat_response != 200:
        pass
    abuse_ch_respones = ip_block.get_ssl_bl()
    if abuse_ch_respones != 200:
        pass
    cisco_response = ip_block.get_talos_list()
    if cisco_response != 200:
        pass
    blocklist_de_response = ip_block.get_blde_list()
    if blocklist_de_response != 200:
        pass
    nothink_response = ip_block.get_nt_ssh_bl()
    if nothink_response != 200:
        pass
    # Consolidating the list and writing it to a file.
    block_list = ip_block.generate_block_list()
    results_file = open('ip_block.txt', 'w', encoding='ascii')
    print('There are %d entries in the block list.' % len(block_list))
    for ip in block_list:
        results_file.write(ip + '\n')
    results_file.close()


if __name__ == '__main__':
    main()
