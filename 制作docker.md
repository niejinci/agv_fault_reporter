[toc]
***

## ai

copilot gemini3.0 pro

## 问题

【背景】

我需要把程序(agv_fault_reporter)部署到公司内网服务器，但是内网服务器不能连接互联网，因此内网服务器无法下载程序需要的依赖。

我本地有一个 ubuntu22.04.tar 文件，镜像是用它作为基础镜像。

【需求】

把程序(agv_fault_reporter) 做成一个 docker。

请你根据 *AGV故障填报和分析系统部署指南.md* 里面的安装依赖，输出制作docker的步骤。

## 答复

既然您指定了使用本地的 `ubuntu22.04.tar` 作为基础镜像，我们需要对步骤稍作调整。

**核心逻辑是：** 在一台**有互联网**的电脑上，导入您的 Ubuntu 基础镜像，安装好所有依赖（Python, Flask, Gunicorn 等）并打包成最终的业务镜像，然后再拷贝到内网服务器运行。

### 步骤一：准备基础镜像（在有网的电脑上）

/home/njc/mk_docker/agv_fault_reporter

1.  **加载基础镜像：**
    假设 `ubuntu22.04.tar` 就在当前目录。
    ```bash
    docker load -i ubuntu22.04.tar
    ```
2.  **确认镜像名称：**
    加载后，请运行 `docker images` 查看镜像的 REPOSITORY 和 TAG。
    *   如果显示为 `ubuntu:22.04`，后续步骤直接用。
    *   如果显示为 `<none>:<none>`（也就是只有 Image ID），您需要给它打个标签：
        ```bash
        # 假设 Image ID 是 a8780b506fa4
        docker tag a8780b506fa4 my-ubuntu-base:22.04
        ```
    *(下文假设您的基础镜像名为 `my-ubuntu-base:22.04`)*

### 步骤二：编写构建文件（在项目根目录）

在 `agv_fault_reporter` 文件夹同级或内部，创建以下三个文件。

#### 1. `requirements.txt` (Python依赖)
```text name=requirements.txt
Flask
gunicorn
Flask-Limiter
```

#### 2. `entrypoint.sh` (启动脚本)
用于解决“数据库初始化”问题。

```bash name=entrypoint.sh
#!/bin/bash

# 定义数据存储目录（建议挂载到这个目录实现持久化）
DATA_DIR="/data"
DB_FILE="$DATA_DIR/faults.db"
LINK_FILE="/app/faults.db"

# 确保数据目录存在
if [ ! -d "$DATA_DIR" ]; then
    mkdir -p "$DATA_DIR"
fi

# 1. 检查数据库是否存在
if [ ! -f "$DB_FILE" ]; then
    echo ">>> 未检测到数据库，正在初始化..."
    # 在当前目录(/app)利用 schema.sql 生成数据库
    sqlite3 faults.db < schema.sql
    # 移动到持久化目录
    mv faults.db "$DB_FILE"
    echo ">>> 数据库初始化完成。"
fi

# 2. 建立软链接，让程序能在 /app 下找到数据库
if [ ! -L "$LINK_FILE" ] && [ ! -f "$LINK_FILE" ]; then
    ln -s "$DB_FILE" "$LINK_FILE"
    echo ">>> 已建立数据库软链接。"
fi

# 3. 启动 Gunicorn
# 使用 exec 确保 gunicorn 接收 PID 1 信号
exec gunicorn --workers 3 --bind 0.0.0.0:5000 app:app
```

#### 3. `Dockerfile` (核心构建文件)
根据您的部署指南，我们需要在 Ubuntu 上安装 Python3, Pip3 和 Sqlite3。

```dockerfile name=Dockerfile
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /app

# 1. 强制重写软件源 (包含 main, restricted, universe, multiverse)
# 这一步直接写入阿里云的完整源配置，确保 python3-pip (位于 universe) 能被找到
RUN echo "deb http://mirrors.aliyun.com/ubuntu/ jammy main restricted universe multiverse" > /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/ubuntu/ jammy-updates main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/ubuntu/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list && \
    echo "deb http://mirrors.aliyun.com/ubuntu/ jammy-security main restricted universe multiverse" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y python3 python3-pip sqlite3 tzdata && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# 2. 安装 Python 依赖 (保留清华源和超时设置)
RUN pip3 install --default-timeout=1000 --no-cache-dir -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple

COPY . .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 5000
VOLUME ["/data"]
ENTRYPOINT ["/entrypoint.sh"]
```

---

### 步骤三：构建与导出（在有网的电脑上）

1.  **构建业务镜像：**
    确保当前目录有 `Dockerfile`, `requirements.txt`, `entrypoint.sh` 和 `agv_fault_reporter` 的代码。
    ```bash
    docker build -t agv-reporter:final .
    ```

2.  **保存为离线包：**
    ```bash
    docker save -o agv-reporter-final.tar agv-reporter:final
    ```

---

### 步骤四：内网服务器部署（最终步骤）

将 `agv-reporter-final.tar` 复制到内网服务器。

1.  **加载镜像：**
    ```bash
    docker load -i agv-reporter-final.tar
    ```

2.  **启动容器（包含数据持久化）：**
    为了防止您删除容器后数据库丢失，我们将宿主机的目录挂载到容器内的 `/data`。

    ```bash
    # 1. 在服务器上创建一个存放数据的目录
    mkdir -p /opt/agv_data

    # 2. 确定镜像名称
    // Podman 加载 Docker 导出的镜像时，有时会给镜像名前面加上 localhost/。为了不报错，请先查看一下加载后的确切名称：
    docker images

    # 3. 启动容器
    docker run -d \
      --name agv-reporter \
      --restart unless-stopped \
      -p 5000:5000 \
      -v /opt/agv_data:/data \
      agv-reporter:final

    or 

    docker run -d \
    --name agv-reporter \
    --restart unless-stopped \
    -p 5000:5000 \
    -v /opt/agv_data:/data \
    docker.io/library/agv-reporter:final
    ```

### 验证

1.  **查看日志：**
    ```bash
     # 查看最近的日志。
    docker logs --tail 100 agv-reporter
    ```
    第一次运行时，您应该能看到 `>>> 未检测到数据库，正在初始化...` 的提示。

2.  **查看数据文件：**
    如果在宿主机的 `/opt/agv_data/` 下看到了 `faults.db`，说明部署成功且数据已持久化。


## 重新打包镜像

如果改动了代码或依赖，需要重新打包镜像。

### 1. 修改代码或依赖

### 2.重新构建镜像（在有网电脑上）
```sh
# 1. 构建新镜像
docker build -t agv-reporter:final .

# 2. 导出新镜像（覆盖旧的tar包）
docker save -o agv-reporter-final.tar agv-reporter:final
```

### 3. 重新部署（在内网服务器上）
将新的 agv-reporter-final.tar 上传到服务器，然后执行以下操作来更新：

1. 删除旧容器和旧镜像
```sh
# 停止并删除旧容器
docker stop agv-reporter
docker rm agv-reporter

# (可选) 删除旧镜像，防止名字混淆
docker rmi docker.io/library/agv-reporter:final
```

2. 加载新镜像
```sh
docker load -i agv-reporter-final.tar
```

3. 启动新容器
```sh
docker run -d \
  --name agv-reporter \
  --restart unless-stopped \
  -p 5000:5000 \
  -v /opt/agv_data:/data \
  docker.io/library/agv-reporter:final
```

4. 验证
启动后再次查看日志：
```sh
docker logs -f agv-reporter
```
如果看到 [INFO] Booting worker with pid: ... 且不再刷出 ModuleNotFoundError 错误，就说明部署成功了。