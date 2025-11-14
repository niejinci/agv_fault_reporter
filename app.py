import sqlite3
import csv
from flask import Flask, render_template, request, redirect, url_for, g, Response, flash, session
from datetime import datetime
import io
import re # 导入正则表达式模块
from functools import wraps # 导入 wraps 用于装饰器
import json
# 1. 导入 Limiter 相关的模块
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import math

app = Flask(__name__)
app.secret_key = 'your_very_secret_key' # flash消息需要一个密钥
DATABASE = 'faults.db'

# 2. 初始化 Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,  # 使用 IP 地址作为识别用户的依据
    default_limits=["200 per day", "50 per hour"] # 为所有路由设置一个默认的全局限制
)

# --- 全局常量定义 ---
# 【核心修改 1】将 FAULT_CATEGORIES 改造为元组列表
FAULT_CATEGORIES = [
    ("决策异常", "无法切换模式，异常不停车，下发任务后车不动；责任人：奉涛。"),
    ("RCS/网络通信异常", "用于记录“RCS掉线”、“通讯中断”等网络问题；责任人：沈松。"),
    ("定位异常", "脱离路线，定位评分低，获取不到定位话题，获取雷达数据失败，雷达数据异常(掉点，时间戳不连续，点云缺失)；责任人：李聪平。"),
    ("MCU异常", "无法正常控制下位机运动，无法正常获取里程计，电量等硬件信息；责任人：冯思远。"),
    ("扫码数据异常", "无法正确获取扫码相机数据；责任人：冯思远。"),
    ("避障异常", "前方无障碍但是报避障，撞车了，误报避障；责任人：刘贝。"),
    ("环境/人为因素", "区分是AGV的问题还是外部环境的问题(如料框乱放、人员干预)；责任人：现场技术人员。"),
    ("充电异常", "充电口对不准；责任人：李聪平。"),
    ("充电避障", "充电避障，不充电；责任人：现场技术人员。"),
    ("运控异常", "移动任务失败，托盘/货架旋转避障，顶升货架歪了，无避障；责任人：梁海聪。"),
    ("其他", "用于无法归类的罕见问题。")
]
FAULT_STATUSES = ["未处理", "观察中", "已处理"]
DEFAULT_STATUS = "未处理"

# --- 数据库管理 (无变动) ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# --- 新增：权限控制装饰器 ---
def root_required(f):
    """检查用户是否是以 'root' 身份登录的装饰器。"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user') != 'root':
            flash('此操作需要管理员权限，请先登录。', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- 核心解析与业务逻辑 ---
def parse_fault_text(raw_text):
    """从原始文本中解析故障信息字段"""
    data = {}
    # 使用正则表达式匹配键值对，注意处理冒号的全角和半角
    pattern = re.compile(r'^(发现人员|时间|车辆信息|报警描述|解决办法|责任人|错误类别)[:：]\s*(.*)', re.MULTILINE)
    matches = dict(pattern.findall(raw_text))

    # 1. 提取基本字段
    data['reporter_name'] = matches.get('发现人员', '').strip()
    data['vehicle_id'] = matches.get('车辆信息', '').strip()
    data['description'] = matches.get('报警描述', '').strip()
    data['solution'] = matches.get('解决办法', '').strip()

    responsible_person_raw = matches.get('责任人', '').strip()

    # --- 关键修改：数据清洗 ---
    # 定义一个正则表达式，只保留：中文字符、大小写字母、数字、空格和@符号
    # \u4e00-\u9fa5 是中文字符的Unicode范围
    clean_pattern = re.compile(r'[^\u4e00-\u9fa5a-zA-Z0-9\s@]+')
    # 将所有匹配到的乱码（如 ￳...￰）替换成一个空格。
    responsible_person_cleaned = clean_pattern.sub(' ', responsible_person_raw).strip()

    # 清洗后再去除可能存在的@前缀（虽然我们的正则已经很宽容了）
    data['responsible_person'] = responsible_person_cleaned.lstrip('@')


    # 2. 解析时间字段 (支持多种格式)
    time_str = matches.get('时间', '').strip()
    fault_dt = None
    if time_str:
        # 1) 规范化：把全角冒号换成半角，把多个空白（包括全角空格）压缩，去掉两侧空白
        norm = time_str.replace('：', ':')
        # 把全角空格 \u3000 替换为普通空格；并把连续空格收拢
        norm = norm.replace('\u3000', ' ')
        norm = re.sub(r'\s+', ' ', norm).strip()
        # 常见可能的格式，尝试逐个解析
        tried = []
        for fmt in ('%Y年%m月%d日%H:%M', '%Y年%m月%d日 %H:%M', '%Y-%m-%d %H:%M', '%Y/%m/%d %H:%M'):
            try:
                fault_dt = datetime.strptime(norm, fmt)
                break
            except Exception as e:
                tried.append((fmt, str(e)))
        # 如果还是解析失败，尝试用正则抽取数字 (年/月/日 时:分)
        if fault_dt is None:
            # 尝试抽取 年 月 日 时 分
            m = re.search(r'(\d{4}).*?(\d{1,2}).*?(\d{1,2}).*?(\d{1,2})[:：](\d{2})', norm)
            if m:
                y, mo, d, hh, mm = m.groups()
                try:
                    fault_dt = datetime(int(y), int(mo), int(d), int(hh), int(mm))
                except ValueError:
                    fault_dt = None
    data['fault_time'] = fault_dt  # 可能为 None

    # 3. 【核心修改 2】根据新的 FAULT_CATEGORIES 结构调整解析逻辑
    category_from_user = matches.get('错误类别', '').strip()

    category_map = {}
    for i, (name, desc) in enumerate(FAULT_CATEGORIES):
        category_map[name.lower()] = name # 映射：小写全名 -> 标准名称
        category_map[str(i + 1)] = name   # 映射：编号 -> 标准名称

    if category_from_user and category_from_user.lower() in category_map:
        data['category'] = category_map[category_from_user.lower()]
    else:
        # 【核心修改】更新回退逻辑以匹配新的分类
        desc = data['description'].lower()

        # 将判断逻辑按优先级从高到低排列
        if '充电' in desc and '避障' in desc:
            data['category'] = '充电避障'
        elif 'rcs' in desc or '通讯' in desc:
            data['category'] = 'RCS/网络通信异常'
        elif '扫码' in desc or '相机数据' in desc:
            data['category'] = '扫码数据异常'
        elif '定位' in desc or '雷达' in desc or '评分低' in desc or '脱离路线' in desc:
            data['category'] = '定位异常'
        elif 'mcu' in desc or '下位机' in desc or '里程计' in desc:
            data['category'] = 'MCU异常'
        elif '撞' in desc or ('避障' in desc and '无障碍' in desc): # "撞车了" 或 "前方无障碍但是报避障"
            data['category'] = '避障异常'
        elif '充电' in desc:
            data['category'] = '充电异常'
        elif '任务' in desc or '托盘' in desc or '货架' in desc or '旋转' in desc or '顶升' in desc:
            data['category'] = '运控异常'
        elif '模式' in desc or '不动' in desc:
            data['category'] = '决策异常'
        elif '料框' in desc or '人为' in desc or '牵引车' in desc:
            data['category'] = '环境/人为因素'
        else:
            data['category'] = '其他'

    return data

# --- 视图函数 ---

# --- 新增：登录与登出路由 ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 硬编码的管理员凭证，请务必修改密码！
        if username == 'root' and password == '123456':
            session['user'] = 'root'
            flash('登录成功！欢迎回来，管理员。', 'success')
            next_url = request.args.get('next')
            return redirect(next_url or url_for('index'))
        else:
            flash('用户名或密码错误。', 'error')

    # 如果已登录，直接重定向到主页
    if session.get('user') == 'root':
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('您已成功登出。', 'info')
    return redirect(url_for('index'))

@app.route('/', methods=['GET', 'POST'])
# 3. 为提交操作应用特定的速率限制
@limiter.limit("10 per minute", methods=['POST'])
def index():
    db = get_db()
    # “详细上报”表单的提交逻辑
    if request.method == 'POST':
        try:
            reporter_name = request.form['reporter_name']
            fault_time_str = request.form['fault_time']
            fault_time = datetime.strptime(fault_time_str, '%Y-%m-%dT%H:%M')
            vehicle_id = request.form['vehicle_id']
            category = request.form['category']
            description = request.form['description']
            solution = request.form['solution']
            responsible_person = request.form['responsible_person']

            db.execute(
                'INSERT INTO faults (reporter_name, fault_time, vehicle_id, category, description, solution, responsible_person, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (reporter_name, fault_time, vehicle_id, category, description, solution, responsible_person, DEFAULT_STATUS)
            )
            db.commit()
            flash('故障已成功提交！', 'success')
        except Exception as e:
            flash(f'提交失败: {e}', 'error')
        # 关键修改1：重定向时，指明要激活 'detailed' tab
        return redirect(url_for('index', tab='detailed'))

    # --- 搜索与筛选逻辑 ---
    search_params = {
        'search_reporter': request.args.get('search_reporter', '').strip(),
        'search_responsible': request.args.get('search_responsible', '').strip(),
        'search_vehicle': request.args.get('search_vehicle', '').strip(),
        'search_status': request.args.get('search_status', '').strip(),
        'search_category': request.args.get('search_category', '').strip(), # 新增
        'search_start_date': request.args.get('search_start_date', '').strip(),
        'search_end_date': request.args.get('search_end_date', '').strip()
    }

    where_clauses = ["1=1"]
    params = []

    if search_params['search_reporter']:
        where_clauses.append("reporter_name LIKE ?")
        params.append(f"%{search_params['search_reporter']}%")
    if search_params['search_responsible']:
        where_clauses.append("responsible_person LIKE ?")
        params.append(f"%{search_params['search_responsible']}%")
    if search_params['search_vehicle']:
        where_clauses.append("vehicle_id LIKE ?")
        params.append(f"%{search_params['search_vehicle']}%")
    if search_params['search_status']:
        where_clauses.append("status = ?")
        params.append(search_params['search_status'])
    if search_params['search_category']: # 新增
        where_clauses.append("category = ?")
        params.append(search_params['search_category'])
    if search_params['search_start_date']:
        where_clauses.append("fault_time >= ?")
        params.append(datetime.strptime(search_params['search_start_date'], '%Y-%m-%d'))
    if search_params['search_end_date']:
        end_date = datetime.strptime(search_params['search_end_date'], '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        where_clauses.append("fault_time <= ?")
        params.append(end_date)

    where_sql = " AND ".join(where_clauses)

    # --- 分页逻辑开始 ---
    # 1. 定义允许的 per_page 值白名单
    allowed_per_page = [10, 20, 50]

    # 2. 获取 per_page 参数，验证并设置默认值
    per_page = request.args.get('per_page', 20, type=int)
    if per_page not in allowed_per_page:
        per_page = 20 # 如果传入了无效值，强制设为默认值

    # 3. 获取当前页码
    page = request.args.get('page', 1, type=int)

    # 4. 查询总数 (必须使用同样的 WHERE 子句)
    total_count_query = f"SELECT COUNT(id) FROM faults WHERE {where_sql}"
    if app.config.get('DEBUG_SQL'):
        print("\n--- DEBUG SQL (Total Count) ---")
        print("Query:", total_count_query)
        print("Params:", params)
        print("---------------------------------\n")
    total_count = db.execute(total_count_query, params).fetchone()[0]

    # 5. 使用动态的 per_page 计算总页数
    total_pages = math.ceil(total_count / per_page)

    # 确保 page 不会超出范围
    if page > total_pages and total_pages > 0:
        page = total_pages

    # 6. 计算 offset
    offset = (page - 1) * per_page

    # 获取当页数据 (使用同样的 WHERE 子句)
    faults_query = f"SELECT * FROM faults WHERE {where_sql} ORDER BY fault_time DESC LIMIT ? OFFSET ?"
    if app.config.get('DEBUG_SQL'):
        print("\n--- DEBUG SQL (Fetch Page Data) ---")
        print("Query:", faults_query)
        print("Params:", params + [per_page, offset])
        print("---------------------------------\n")

    faults = db.execute(faults_query, params + [per_page, offset]).fetchall()

    active_tab = 'quick'

    # 8. 将 per_page 也传递给模板
    return render_template(
        'index.html',
        faults=faults,
        categories=FAULT_CATEGORIES,
        statuses=FAULT_STATUSES, # 将状态列表也传给前端
        active_tab=active_tab,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        allowed_per_page=allowed_per_page,
        search_params=search_params # 将搜索参数传回，用于填充表单
    )

# --- 新增：删除故障的路由 ---
@app.route('/delete/<int:fault_id>', methods=['POST'])
@root_required  # 应用权限装饰器
@limiter.limit("20 per minute") # 对删除操作也进行速率限制
def delete_fault(fault_id):
    try:
        db = get_db()
        # 先检查记录是否存在
        fault = db.execute('SELECT id FROM faults WHERE id = ?', (fault_id,)).fetchone()
        if fault is None:
            flash('删除失败：记录不存在或已被删除。', 'error')
            return redirect(url_for('index'))

        db.execute('DELETE FROM faults WHERE id = ?', (fault_id,))
        db.commit()
        flash(f'记录 ID:{fault_id} 已被成功删除。', 'success')
    except Exception as e:
        flash(f'删除记录时发生错误: {e}', 'error')

    return redirect(url_for('index'))

# 新增：“快速解析”的路由
@app.route('/parse', methods=['POST'])
@limiter.limit("10 per minute")
def parse_fault():
    raw_text = request.form.get('raw_text', '')
    parsed_data = parse_fault_text(raw_text)
    print("\n--- DEBUG SQL (Post Page Data) ---")
    if app.config.get('DEBUG_SQL'):
        for k, v in parsed_data.items():
            print(k, ":", v)
    print("---------------------------------\n")

    # 检查关键字段是否解析成功
    required_fields = ['reporter_name', 'fault_time', 'vehicle_id', 'description', 'responsible_person']
    missing = [f for f in required_fields if not parsed_data.get(f)]
    if missing:
        # 构造更友好的错误信息，尤其指出时间解析的问题
        msgs = []
        if 'fault_time' in missing:
            msgs.append("时间字段解析失败，请检查格式（例如：2025年11月4日 08:53 或 2025-11-04 08:53）。")
        # 其余必填字段
        other_missing = [m for m in missing if m != 'fault_time']
        if other_missing:
            human_map = {
                'reporter_name': '发现人员',
                'vehicle_id': '车辆信息',
                'description': '报警描述',
                'responsible_person': '责任人'
            }
            msgs.append("缺失字段: " + ", ".join(human_map.get(x, x) for x in other_missing))
        # 使用 flash 将错误信息显示在页面上
        flash("解析失败！" + " ".join(msgs), 'error')
        return redirect(url_for('index', tab='quick'))

    try:
        db = get_db()
        insert_query = f"INSERT INTO faults (reporter_name, fault_time, vehicle_id, category, description, solution, responsible_person, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        params = (
            parsed_data['reporter_name'],
            parsed_data['fault_time'],
            parsed_data['vehicle_id'],
            parsed_data['category'],
            parsed_data['description'],
            parsed_data['solution'],
            parsed_data['responsible_person'],
            DEFAULT_STATUS
        )
        if app.config.get('DEBUG_SQL'):
            print("\n--- DEBUG SQL (Insert Parsed Data) ---")
            print("Query:", insert_query)
            print("Params:", params)
            print("---------------------------------\n")

        db.execute(insert_query, params)
        db.commit()
        flash('通过快速解析成功提交故障！', 'success')
    except Exception as e:
        flash(f'数据库插入失败: {e}', 'error')

    # 关键修改5：成功提交后，告诉首页激活 'quick' tab
    return redirect(url_for('index', tab='quick'))


# (edit_fault, statistics, download 等函数保持不变)
@app.route('/edit/<int:fault_id>', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def edit_fault(fault_id):
    db = get_db()
    if request.method == 'POST':
        try:
            # 获取所有可编辑字段
            status = request.form['status']
            resolution_log = request.form['resolution_log']
            reporter_name = request.form['reporter_name']
            fault_time_str = request.form['fault_time']
            fault_time = datetime.strptime(fault_time_str, '%Y-%m-%dT%H:%M')
            vehicle_id = request.form['vehicle_id']
            category = request.form['category']
            description = request.form['description']
            responsible_person = request.form['responsible_person']

            # 构建更新查询
            update_query = """
                UPDATE faults SET
                    status = ?,
                    resolution_log = ?,
                    reporter_name = ?,
                    fault_time = ?,
                    vehicle_id = ?,
                    category = ?,
                    description = ?,
                    responsible_person = ?
                WHERE id = ?
            """
            params = (
                status, resolution_log, reporter_name, fault_time, vehicle_id,
                category, description, responsible_person, fault_id
            )

            if app.config.get('DEBUG_SQL'):
                print("\n--- DEBUG SQL (Edit Fault) ---")
                print("Query:", update_query)
                print("Params:", params)
                print("---------------------------------\n")

            db.execute(update_query, params)
            db.commit()
            flash('记录已成功更新！', 'success')
        except Exception as e:
            flash(f'更新失败: {e}', 'error')
            # 如果更新失败，也需要重新加载编辑页面，并显示错误
            fault_from_db = db.execute('SELECT * FROM faults WHERE id = ?', (fault_id,)).fetchone()
            if fault_from_db is None: return "Fault not found", 404

            # ** 错误修复 **
            # 将 fault_from_db（一个 sqlite3.Row 对象）转换为可变字典
            fault_dict = dict(fault_from_db)
            # 手动将时间字符串转换为 datetime 对象
            fault_dict['fault_time'] = datetime.strptime(fault_dict['fault_time'], '%Y-%m-%d %H:%M:%S')

            return render_template('edit.html', fault=fault_dict, statuses=FAULT_STATUSES, categories=FAULT_CATEGORIES)

        return redirect(url_for('index'))

    fault_from_db = db.execute('SELECT * FROM faults WHERE id = ?', (fault_id,)).fetchone()
    if fault_from_db is None: return "Fault not found", 404

    # ** 错误修复 **
    # 将 fault_from_db（一个 sqlite3.Row 对象）转换为可变字典
    fault_dict = dict(fault_from_db)
    # 手动将时间字符串转换为 datetime 对象，数据库默认存储格式为 '%Y-%m-%d %H:%M:%S'
    fault_dict['fault_time'] = datetime.strptime(fault_dict['fault_time'], '%Y-%m-%d %H:%M:%S')

    # 传递 categories 和 statuses 到模板
    return render_template('edit.html', fault=fault_dict, statuses=FAULT_STATUSES, categories=FAULT_CATEGORIES)

@app.route('/statistics')
def statistics():
    db = get_db()
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    # 新增：获取勾选框状态
    exclude_factory = request.args.get('exclude_factory')

    # 安全加固
    # 1. 定义一个允许用于分组的列名白名单
    allowed_group_by_columns = ['category', 'status', 'vehicle_id', 'reporter_name', 'responsible_person', 'by_date']

    # 2. 从请求中获取 group_by 参数，默认为 'category'
    group_by = request.args.get('group_by', 'category')

    # 3. 验证参数是否在白名单内，如果不在，则强制使用默认值
    if group_by not in allowed_group_by_columns:
        group_by = 'category'
        flash('检测到无效的统计维度，已重置为默认值。', 'warning')

    # 根据 group_by 参数构建查询
    group_by_clause = ""
    if group_by == 'by_date':
        # 如果是按天统计，则使用 DATE 函数
        group_by_clause = "DATE(fault_time)"
    else:
        # 其他情况直接使用列名
        group_by_clause = group_by

    # 4. 现在可以安全地在 f-string 中使用 group_by 变量
    query = f"SELECT {group_by_clause} as group_key, COUNT(*) as count FROM faults WHERE 1=1"
    params = []
    if start_date_str:
        query += " AND fault_time >= ?"
        params.append(datetime.strptime(start_date_str, '%Y-%m-%d'))
    if end_date_str:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        query += " AND fault_time <= ?"
        params.append(end_date)

    # 新增：如果勾选了，则添加排除条件
    if exclude_factory:
        query += " AND responsible_person NOT LIKE ?"
        params.append('%工厂%')

    if group_by == 'by_date':
        query += f" GROUP BY group_key ORDER BY group_key ASC" # 按天统计时，按日期升序排列
    else:
        query += f" GROUP BY {group_by} ORDER BY count DESC"    # 按数量降序排序

    if app.config.get('DEBUG_SQL'):
        print("\n--- DEBUG SQL (statistics) ---")
        print("Query:", query)
        print("Params:", params)
        print("---------------------------------\n")

    cursor = db.execute(query, params)
    stats = cursor.fetchall()

    # --- 关键修改：为图表准备数据 ---
    chart_labels = []
    chart_data = []
    if stats:
        chart_labels = [row['group_key'] for row in stats]
        chart_data = [row['count'] for row in stats]

    return render_template(
        'statistics.html',
        stats=stats,
        current_group_by=group_by,
        start_date=start_date_str,
        end_date=end_date_str,
        # 将图表数据传递给模板，并使用 tojson 过滤器确保安全
        exclude_factory=exclude_factory,  # 新增：将状态传递回模板
        chart_labels=json.dumps(chart_labels),
        chart_data=json.dumps(chart_data)
    )

@app.route('/download')
@limiter.limit("5 per minute")
def download():
    db = get_db()
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    query = "SELECT id, reporter_name, fault_time, vehicle_id, category, status, description, solution, resolution_log, responsible_person FROM faults WHERE 1=1"
    params = []
    if start_date_str:
        query += " AND fault_time >= ?"
        params.append(datetime.strptime(start_date_str, '%Y-%m-%d'))
    if end_date_str:
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').replace(hour=23, minute=59, second=59)
        query += " AND fault_time <= ?"
        params.append(end_date)
    query += " ORDER BY fault_time DESC"
    if app.config.get('DEBUG_SQL'):
        print("\n--- DEBUG SQL (Download Data) ---")
        print("Query:", query)
        print("Params:", params)
        print("---------------------------------\n")
    faults_to_download = db.execute(query, params).fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', '发现人员', '故障时间', '车辆信息', '错误类别', '解决状态', '报警描述', '解决办法', '处理记录', '责任人'])
    for row in faults_to_download: writer.writerow(row)
    csv_content = output.getvalue()
    encoded_content = csv_content.encode('utf-8-sig')
    return Response(encoded_content, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=agv_faults_{datetime.now().strftime('%Y%m%d')}.csv"})

if __name__ == '__main__':
    # 只有在直接运行时，才设置这个配置项为 True
    app.config['DEBUG_SQL'] = True
    print("SQL debugging is ON. Running in development mode.")
    app.run(host='0.0.0.0', port=5000, debug=True)