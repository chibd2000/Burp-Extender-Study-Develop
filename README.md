# Burp-Plugin-Develop


## 基于Burp开发的被动扫描探测jwt签名算法None  
  
开发目的：  
  
1、学习java  
2、了解Burp插件开发流程  
3、在测试中经常遇到Jwt的验证机制，自己每次都需要生成在替换会比较麻烦，所以想写一个自动化检测的插件 
  
进度：3/4差不多，还有个base64编码需要改下，程序目前还跑不了，下个星期再来改
  
## 基于Burp开发的图形化添加AWVS扫描  
  
开发目的：  
  
1、学习java  
2、了解Burp插件开发流程  
3、在测试中如果想扫描的话，还需要手动运行一次导入脚本，会比较麻烦，所以想写一个右键发送直接来进行扫描的插件  
  
进度：0，下个星期继续写  
  
构想：  
1、AWVS类：包含了动作事件
2、Config配置类：包含了AWVS所需要的配置  
3、Task类，每个扫描目标的相关信息  
4、Configure类：每个目标相关的扫描的配置信息
