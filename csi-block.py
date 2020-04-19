from logging import basicConfig, getLogger, INFO
from configparser import ConfigParser

from libs.osintchck import OSINTBlock


def update_block_list(
        path_to_block_list, csi_ip_list
        ):
    """Upates file with data from OSINTBlock instances.
    This function updates a file that already contains IP addresses
    that are being blocked with data returned by an OSINTBlock instance
    (and the associated methods.) This is accompslihed by reading a
    file, removing old data obtained by the generate_block_list method
    and writing the new data to the end of the file.

    Keyword arguments:
    path_to_block_list - A string that is the location of a file that
    contains a list of specifically formatted IP addresses.
    csi_ip_list - A list of IP addresses returned by
    generate_block_list.

    Outputs:
    Nothing is returned, however, block list is updated with the new
    IP addresses returned by generate_block_list.

    Raises:
    OSError - Occurs if path_to_block_list does not exist or cannot be
    edited due to permissions errors."""
    log = getLogger('auto_ip_block')
    try:
        block_file = open(path_to_block_list, 'r', encoding='ascii')
    except OSError:
        log.exception('Unable to open block file. This needs to be fixed.')
        exit(1)
    temp_block_list = []
    for line in block_file:
        temp_block_list.append(line.strip('\n'))
    block_file.close()
    for entry in temp_block_list:
        if '#ABL' in entry:
            index_num = temp_block_list.index(entry)
            temp_block_list.remove(index_num)
    for entry in csi_ip_list:
        temp_block_list.append(entry)
    try:
        block_file = open(path_to_block_list, 'w', encoding='ascii')
    except OSError:
        log.exception('Unable to open block file. This needs to be fixed.')
        exit(1)
    for entry in temp_block_list:
        block_file.write(entry + '\n')
    block_file.close()


def main():
    """Doing the thing."""
    # Setting logging.
    log = getLogger('auto_ip_block')
    basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=INFO,
        filename='csi_auto_block.log'
    )
    ip_block = OSINTBlock()
    # Getting the block file's path from a config.
    config = ConfigParser()
    config.read('config.cnf')
    block_path = config['block']['path']
    # Retrieving the block lists.
    # Emerging threat's known compromised host list.
    emerging_threat_response = ip_block.get_et_ch()
    if emerging_threat_response != 200:
        log.error(
            '%d response code from ET', emerging_threat_response
        )
    # URLHaus Botnet C2 list.
    abuse_ch_response = ip_block.get_ssl_bl()
    if abuse_ch_response != 200:
        log.error(
            '%d response code from abuse.ch', abuse_ch_response
        )
    # Cisco Talos IP block list.
    cisco_response = ip_block.get_talos_list()
    if cisco_response != 200:
        log.error(
            '%d response code from Cisco Talos', cisco_response
        )
    # Blocklist.de ban list.
    blocklist_de_response = ip_block.get_blde_list()
    if blocklist_de_response != 200:
        log.error(
            '%d response code from blocklist.de', blocklist_de_response
        )
    # Nothink.org's list of servers that conduct brute force attacks
    # against SSH servers.
    nothink_response = ip_block.get_nt_ssh_bl()
    if nothink_response != 200:
        log.error(
            '%d response code from Nothink.org', nothink_response
        )
    # Consolidating the list and writing it to a file.
    auto_block_list = ip_block.generate_block_list()
    update_block_list(block_path, auto_block_list)


if __name__ == '__main__':
    main()
