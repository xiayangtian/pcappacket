# -*- coding:utf-8 -*-
import pymongo
conn = pymongo.MongoClient("localhost",27017)
db=conn.myinfo
db.user.insert_one({"name":"wang"})

print(db.user)