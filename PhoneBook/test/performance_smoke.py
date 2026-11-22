"""Optional local SQLite benchmark. This is NOT a MySQL performance certification."""
import tempfile
from time import perf_counter
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from sqlalchemy import insert
from phonebook.database import Database
from phonebook.models import Contact
from phonebook.services import AuthService,ContactService

with tempfile.TemporaryDirectory() as folder:
    db=Database('sqlite:///'+str(Path(folder)/'benchmark.db'))
    db.initialize()
    uid=AuthService(db).register('Performance Test','perf@example.com','benchmark-pass','benchmark-pass')
    with db.session() as session:
        with session.begin():
            session.execute(insert(Contact),[
                {'user_id':uid,'name':f'Contact {i:05d}',
                 'phone':f'09{i:08d}', 'email':f'contact{i}@example.com'} for i in range(10000)
            ])
    service=ContactService(db)
    durations={}
    t=perf_counter(); results=service.search(uid,'contact 09999');durations['Search 10k']=perf_counter()-t
    t=perf_counter(); allrows=service.list_contacts(uid);durations['Load 10k']=perf_counter()-t
    t=perf_counter();cid=service.create(uid,name='Extra',phone='123456789');durations['Add']=perf_counter()-t
    t=perf_counter();service.update(uid,cid,name='Updated',phone='123456789');durations['Edit']=perf_counter()-t
    t=perf_counter();service.delete(uid,cid,confirmed=True);durations['Delete']=perf_counter()-t
    print('SQLite local-only benchmark (NOT MySQL and NOT GUI rendering)')
    print('All contact count:',len(allrows),'Matched:',len(results))
    for op,d in durations.items(): print(f'{op:13s}: {d*1000:.1f} ms')
    db.dispose()
