# Burp-Plugin-Develop


## 基于Burp开发的主动探测jwt签名算法None和签名的有效性

开发目的：  

1、学习java  
2、了解Burp插件开发流程  
3、在测试中经常遇到Jwt的验证机制，自己每次都需要生成在替换会比较麻烦，所以想写一个自动化检测的插件 

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/JWTNone.png)

使用说明：

1、在检测的时候需要在Repeater进行发包一次，因为这里实现的逻辑是通过返回包的大小与原来返回包的大小进行比较，所以需要先得到正常的数据包的返回大小才可以  

更新内容：  

1、添加了一个无签名验证的模块放了上去（最近刚碰到的一个情景，没有对第三段签名进行校验，导致第二段中传输的数据可以直接进行伪造），现在有探测None签名算法模块和无签名验证算法模块，现在一共两个jwt相关的模块实现（2021.7.31-添加模块）  

2、如果jwt鉴权数据存在于URL中的时候，此时在构建请求包发送的时候会失败（2021.7.31-已修改）

## 基于Burp开发的图形化主动添加AWVSXray扫描

开发目的：  

1、学习java  
2、了解Burp插件开发流程  
3、在单个网站测试中如果想扫描的话，还需要手动运行一次导入脚本，而且对后台有相关验证的站点每次设置相关鉴权信息，会比较麻烦，所以想写一个右键发送直接来带上相关鉴权信息到awvs进行爬取放到xray中进行扫描的插件    

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/AWVSXray.png)   

更新内容：

1、如果header头字段中的内容带上了双引号，则添加扫描的时候失败，这里通过转义header内容中的双引号来进行解决（2021.7.30-已修改） 

使用说明：

1、将工程文件中的db.properties中的相关xray和awvs进行配置放到burp目录即可，可以看extender中是否有提示读取到相关配置信息即可

## 基于Burp开发的主动shiro已知版本探测权限绕过

开发目的：  

1、学习java  
2、了解Burp插件开发流程  
3、在测试中经常遇到shiro，自己每次都需要生成在替换会比较麻烦，所以想写一个自动化检测的插件  

CVE-2016-6802（shiro<1.5.0）  ：`http://localhost/admin/`  

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/CVE_2016_6802.png)   

CVE-2020-1957（shiro<1.5.2）  ：`http://localhost/;/admin/`  

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/CVE-2020-1957.png)   

CVE-2020-11989（shiro<1.5.3）：`http://localhost/test;/admin`   （11989的权限绕过需要基于ContextPath的存在）

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/CVE-2020-11989.png)   

CVE-2020-13933（shiro<1.6）   ：`http://localhost/hello/%3b11111`   

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/CVE-2016-13933.png)   

CVE-2020-17510（shiro<1.7.0）：没写  

CVE-2020-17523（shiro<1.7.0）：没写

## 基于Burp开发的被动敏感路径探测

1、学习java  
2、了解Burp插件开发流程  
3、在测试中可能一些路径会遗漏，所以想写一个被动扫描的检测插件

spring：敏感路径泄露

svn：源码泄露

git：源码泄露 

interface-doc：接口API泄露



还没写，这个星期六星期天可能会补上
