[toc]
***

# 依赖安装

以 ubuntu 系统为例：

1. 更新软件包索引
```sh
sudo apt update
```

2. 安装 python 和 pip3
```sh
sudo apt install python3 python3-pip
```

3. 安装 Flask 和 Gunicorn
```sh
pip3 install Flask
pip3 install gunicorn
```

4. 安装 sqlite3
```sh
sudo apt install sqlite3 -y
```

# 部署程序

将包 agv_fault_reporter.tar 上传到服务器后，解包:
```sh
tar -xvf agv_fault_reporter.tar
```

项目结构
```sh
tree agv_fault_reporter
agv_fault_reporter
├── app.py
├── schema.sql
├── static
│   └── style.css
└── templates
    ├── edit.html
    ├── index.html
    ├── login.html
    └── statistics.html

2 directories, 7 files

```

# 初始化数据库

在服务器上进入项目目录(例如： agv_fault_reporter)，运行以下命令创建表：
```sh
sqlite3 faults.db < schema.sql
```
**注意**这个手动初始化的步骤只需要在第一次部署或数据库文件丢失后执行一次。之后每次运行程序，它都会直接使用已经存在的 faults.db 文件。

# 启动程序

```sh
# 在项目目录下运行
gunicorn --workers 3 --bind 0.0.0.0:5000 app:app --daemon
```
这会在后台启动 3个工作进程，监听 5000 端口。--daemon 参数让它在后台运行。

现在，你的服务就在 http://server_ip:5000 上运行了，你可以通过这个地址访问并提交故障报告。

# 调试

1. 查看进程
```sh
ps -ef | grep guni
```

2. 杀掉进程
```sh
pkill gunicorn
```

3. 调试模式运行程序

在项目目录下
```sh
python app.py
```
