import asyncio
import orm
#测试部分
from models import User

if __name__== '__main__':

    async def test():
        await orm.create_pool(loop, user='www-data', password='www-data', db='awesome')
        u = User(name='Test', email='tast@example.com', passwd='123456780', image='about:blank')
        await u.save()
        a = await u.findAll() #这个要打印才显示出来
        print(a)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(test())
    orm.__pool.close()  #在关闭event loop之前，首先需要关闭连接池。
    loop.run_until_complete(orm.__pool.wait_closed())#在关闭event loop之前，首先需要关闭连接池。
    loop.close()