import os, json, sys
from time import sleep

from bs4 import BeautifulSoup
from pprint import pprint

base_url = 'https://security-tracker.debian.org/tracker/'
data_dict = {}


def do_filter(CVE:str, html_doc:str) -> None:
    data_list = []
    bs = BeautifulSoup(html_doc, "html.parser")
    table_node = bs.find_all('table')
    package_name = ""
    for tr_row in (table_node[1].find_all('tr')):
        default_value = []
        for td_leb in tr_row.find_all('td'):
            default_value.append(td_leb.get_text())
        # filter_key = False
        # for data in default_value:
        #     if 'stretch' in data:
        #         filter_key = True
        if default_value:
            if default_value[0]:
                package_name = default_value[0]
            else:
                default_value[0] = package_name
        if default_value and [s for s in default_value if "stretch" in s]:
            data_list.append(default_value)
    data_dict[CVE] = data_list
    # print(CVE)
    # print(data_list)


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print("Need the file name")
        exit(0)
    file_name = sys.argv[1]

    with open(file_name) as fp:
        cve_list = fp.readlines()

    cve_list = [r.strip('\n').strip(' ') for r in cve_list]
    print(cve_list)
    i = 0
    for cve in cve_list:
        i += 1
        if i <= 20000:
            try:
                url = base_url + cve
                html_doc = os.popen('proxychains curl ' + url)
                do_filter(cve, html_doc)
                sleep(1)
            except Exception as e:
                print(e)
                print(cve)
                # exit(0)

    # pprint(data_dict)
    for k, v in data_dict.items():
        for data in v:
            print(k + ' ' + ' '.join(data))

    # json_str = json.dumps(data_dict)
    # with open('cve_data.json', 'w') as fp:
    #     fp.write(json_str)
    #
    # json_str = json.dumps(data_dict, indent=4)
    # with open('cve_data_indent.json', 'w') as fp2:
    #     fp2.write(json_str)
