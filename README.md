# Burp-Plugin-Develop


## 基于Burp开发的探测jwt签名算法None  
  
开发目的：  
  
1、学习java  
2、了解Burp插件开发流程  
3、在测试中经常遇到Jwt的验证机制，自己每次都需要生成在替换会比较麻烦，所以想写一个自动化检测的插件 
  
使用说明：  
  
1、用的时候需要注意，需要先发包，因为比较none是否存在是需要比较返回包的  
  
BUG：  
1、如果在jwt作为参数存在url中，则数据包发送失败，这星期六星期天改上

![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/JWTNone.png)  
  
## 基于Burp开发的图形化添加AWVSXray扫描  
  
开发目的：  
  
1、学习java  
2、了解Burp插件开发流程  
3、在测试中如果想扫描的话，还需要手动运行一次导入脚本，会比较麻烦，所以想写一个右键发送直接来进行扫描的插件  
  
![image](https://github.com/chibd2000/Burp-Extender-Study-Develop/blob/main/img/AWVSXray.png)  
  
1、db.properties配置文件配好自己的awvs和xray的服务器放在对应的burp目录中  

## 基于Burp开发的shiro已知版本探测权限绕过
  
开发目的：  
  
1、学习java  
2、了解Burp插件开发流程  
3、在测试中经常遇到shiro，自己每次都需要生成在替换会比较麻烦，所以想写一个自动化检测的插件  
  
这周星期六星期天补上

