#!/usr/bin/env python3
# -*- coding: utf-8 -*-

' url handlers '
import logging
import re, time, json, hashlib
from aiohttp import web

import markdown2
from apis import Page, APIValueError, APIError, APIPermissionError, APIResourceNotFoundError
from config import configs
from coroweb import get, post
from models import User, Blog, next_id, Comment


def get_page_index(page_str):
    p = 1
    try:
        p = int(page_str)
    except ValueError as e:
        pass
    if p < 1:
        p = 1
    return p


def user2cookie(user, max_age):
    """
    Generate cookie str by user(id-expires-sha1).
    """
    # build cookie string by: id-expires-sha1
    # 过期时间是创建时间+存活时间
    expires = str(int(time.time() + max_age))
    s = '%s-%s-%s-%s' % (user.id, user.passwd, expires, _COOKIE_KEY)
    # SHA1是一种单向算法，可以通过原始字符串计算出SHA1结果，但无法通过SHA1结果反推出原始字符串。
    L = [user.id, expires, hashlib.sha1(s.encode('utf-8')).hexdigest()]
    return '-'.join(L)

async def cookie2user(cookie_str):
    """
    Parse cookie and load user if cookie is valid.
    """
    if not cookie_str:
        return None
    try:
        L = cookie_str.split('-')
        if len(L) != 3:
            return None
        uid, expires, sha1 = L
        if int(expires) < time.time():
            return None
        user = await User.find(uid)
        if user is None:
            return None
        s = '%s-%s-%s-%s' % (uid, user.passwd, expires, _COOKIE_KEY)
        if sha1 != hashlib.sha1(s.encode('utf-8')).hexdigest():
            logging.info('invalid sha1')
            return None
        user.passwd = '********'
        return user
    except Exception as e:
        logging.exception(e)
        return None


#获取注册用户
@get('/api/users')
async def api_get_users(*, page='1'):
    page_index = get_page_index(page)
    # count为MySQL中的聚集函数，用于计算某列的行数
    # user_count代表了有多个用户id
    user_count = await User.findNumber('count(id)')
    p = Page(user_count, page_index)
    # 通过Page类来计算当前页的相关信息, 其实是数据库limit语句中的offset，limit
    if user_count == 0:
        return dict(page=p, users=())
    # page.offset表示从那一行开始检索，page.limit表示检索多少行
    users = await User.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))

    for u in users:
        u.passwd = '*******'
    return dict(page=p, users=users)


_RE_EMAIL = re.compile(r'^[0-9a-z\.\_\-]+\@[a-z0-9\-\_]+(\.[a-z0-9\-\_]+){1,4}$')
_RE_SHA1 = re.compile(r'^[0-9a-f]{40}$')
COOKIE_NAME = 'myblogsession' #用来在set_cookie中命名
_COOKIE_KEY = configs.session.secret #导入默认设置

@get('/register')
def register():
    return {
        "__template__": 'register.html'
    }

@post('/api/users')
async def api_register_user(*, email, name, passwd):
    if not name or not name.strip():
        raise APIValueError('name')
    if not email or not _RE_EMAIL.match(email):
        raise APIValueError('email')
    if not passwd or not _RE_SHA1.match(passwd):
        raise APIValueError('passwd')

    # 该邮箱是否已注册
    users = await User.findAll('email=?', [email])
    if len(users) > 0:
        raise APIError('register:failed', 'email', 'Email is already in use.')

    uid = next_id()
    # 数据库中存储的passwd是经过SHA1计算后的40位Hash字符串，所以服务器端并不知道用户的原始口令。
    sha1_passwd = '%s:%s' % (uid, passwd)
    user = User(id=uid, name=name.strip(), email=email, passwd=hashlib.sha1(sha1_passwd.encode('utf-8')).hexdigest(),
                image='http://www.gravatar.com/avatar/%s?d=mm&s=120' % hashlib.md5(email.encode('utf-8')).hexdigest())
    await user.save()

    # make session cookie:
    # 制作cookie返回浏览器客户端
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = '********'
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r

#登录
@get('/signin')
def signin():
    return {
        "__template__": 'signin.html'
    }

@post('/api/authenticate')
async def authenticate(*, email, passwd):
    if not email:
        raise APIValueError('email', 'Invalid email.')
    if not passwd:
        raise APIValueError('passwd', 'Invalid password.')
    users = await User.findAll('email=?', [email])
    if len(users) == 0:
        raise APIValueError('email', 'Email not exist.')
    user = users[0]

    # 在Python 3.x版本中，把'xxx'和u'xxx'统一成Unicode编码，即写不写前缀u都是一样的，
    # 而以字节形式表示的字符串则必须加上b前缀：b'xxx'。
    # sha1 = hashlib.sha1()
    # sha1.update(user.id.encode('utf-8'))
    # sha1.update(b':')
    # sha1.update(passwd.encode('utf-8'))

    # 检查密码,把登录密码转化格式并进行摘要算法
    browser_sha1_passwd = '%s:%s' % (user.id, passwd)
    browser_sha1 = hashlib.sha1(browser_sha1_passwd.encode('utf-8'))
    if user.passwd != browser_sha1.hexdigest():
        raise APIValueError('passwd', 'Invalid password')

    # authenticate ok, set cookie
    #制作cookie发送给浏览器，这步骤与注册用户一样
    r = web.Response()
    r.set_cookie(COOKIE_NAME, user2cookie(user, 86400), max_age=86400, httponly=True)
    user.passwd = "********"
    r.content_type = 'application/json'
    r.body = json.dumps(user, ensure_ascii=False).encode('utf-8')
    return r

def check_admin(request):
    if request.__user__ is None or not request.__user__.admin:
        raise APIPermissionError()

#MVC使得界面可达
@get('/manage/blogs/create')
def manage_create_blog():
    return {
        '__template__': 'manage_blog_edit.html',
        'id': '',
        'action': '/api/blogs'  # 对应HTML页面中VUE的action名字
    }

@post('/api/blogs')
async def api_create_blog(request, *, name, summary, content):
    check_admin(request)
    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')
    blog = Blog(user_id=request.__user__.id, user_name=request.__user__.name, user_image=request.__user__.image,
                name=name.strip(), summary=summary.strip(), content=content.strip())
    await blog.save()
    # 返回一个dict,没有模板，会把信息直接显示出来
    return blog

@get('/api/blogs')
async def api_blogs(*, page='1'):
    page_index = get_page_index(page)
    blogs_count = await Blog.findNumber('count(id)')
    p = Page(blogs_count, page_index)
    if blogs_count == 0:
        return dict(page=p, blogs=())
    blogs = await Blog.findAll(orderBy='created_at desc', limit=(p.offset, p.limit))
    return dict(page=p, blogs=blogs)

#管理页面
@get('/manage/blogs')
def manage_blogs(*, page='1'):
    return {
        '__template__': 'manage_blogs.html',
        'page_index': get_page_index(page)
    }

@post('/api/blogs/delete/{id}')
async def api_delete_blog(id, request):
    logging.info('删除博客的ID为：%s' % id)
    check_admin(request)
    b = await Blog.find(id)
    if b is None:
        raise APIResourceNotFoundError('Blog')
    await b.remove()
    return dict(id=id)

@post('/api/blogs/modify')
async def api_modify_blog(request, *, id, name, summary, content):
    logging.info('修改的博客的ID为：%s' % id)

    if not name or not name.strip():
        raise APIValueError('name', 'name cannot be empty.')
    if not summary or not summary.strip():
        raise APIValueError('summary', 'summary cannot be empty.')
    if not content or not content.strip():
        raise APIValueError('content', 'content cannot be empty.')

    blog = await Blog.find(id)
    blog.name = name
    blog.summary = summary
    blog.content = content

    await blog.update()
    return blog


@get('/manage/blogs/modify/{id}')
def manage_modify_blog(id):
    return {
        '__template__': 'manage_blog_modify.html',
        'id': id,
        'action': '/api/blogs/modify'
    }


@get('/signout')
def signout(request):
    referer = request.headers.get('Referer')
    r = web.HTTPFound(referer or '/')
    # 清理掉cookie来退出账户
    r.set_cookie(COOKIE_NAME, '-deleted-', max_age=0, httponly=True)
    logging.info('user signed out.')
    return r

@get('/')
async def index(*, page='1'):
    # summary = "Lorem ipsum dolor sit amet, consectetur adipisicing elit," \
    #           " sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    #
    # blogs = [
    #     Blog(id='1', name='Test Blog', summary=summary, created_at=time.time() - 120),
    #     Blog(id='2', name='Something New', summary=summary, created_at=time.time() - 3600),
    #     Blog(id='3', name='Learn Swift', summary=summary, created_at=time.time() - 7200)
    # ]
    page_index = get_page_index(page)
    # 查找博客表里的条目数
    num = await Blog.findNumber('count(id)')
    # 没有条目则不显示
    if not num or num == 0:
        logging.info('the type of num is :%s' % type(num))
        blogs = []
    else:
        page = Page(num, page_index)
        # 根据计算出来的offset(取的初始条目index)和limit(取的条数)，来取出条目
        # 首页只显示前5篇文章
        blogs = await Blog.findAll(orderBy='created_at desc', limit=(0, 5))
    return {
        '__template__': 'blogs.html',
        'page': page,
        'blogs': blogs
        # '__template__'指定的模板文件是blogs.html，其他参数是传递给模板的数据
    }


@get('/manage/users')#管理用户
def manage_users(*, page='1'):
    return {
        '__template__': 'manage_users.html',
        'page_index': get_page_index(page)
    }

def text2html(text):
    # HTML转义字符
    # "		&quot;
    # & 	&amp;
    # < 	&lt;
    # > 	&gt;
    # 不断开空格	&nbsp;

    lines = map(lambda s: '<p>%s</p>' % s.replace('&', '%amp;').replace('<', '&alt;').replace('>', '&gt;'),
                filter(lambda s: s.strip() != '', text.split('\n')))
    return ''.join(lines)

@get('/blog/{id}')
async def get_blog(id):
    blog = await Blog.find(id)
    comments = await Comment.findAll('blog_id=?', [id], orderBy='created_at desc')
    for c in comments:
        c.html_content = text2html(c.content)
    blog.html_content = markdown2.markdown(blog.content)
    return {
        '__template__': 'blog.html',
        "blog": blog,
        'comments': comments
    }

@get('/api/blogs/{id}')
async def api_get_blog(*, id):
    blog = await Blog.find(id)
    return blog