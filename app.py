from flask import (
    Flask,
    url_for,
    render_template,
    flash,
    abort,
    redirect,
    g,
    request,
    Markup,
    make_response,
    send_file,
    session,
)
from werkzeug.exceptions import NotFound
import json
import sqlite3
import subprocess
import re
import datetime
import attr
import os
import redis
import pytz
import fileformats
from csrf import CSRF
from framesession import FrameSession
from auth import Auth
app = Flask(__name__)
app.config.from_pyfile('config.py')

r = redis.Redis(host='localhost', port=6379, db=0)
fsess = FrameSession(r)
localtime = pytz.timezone(app.config['TIMEZONE'])
def dt_now():
    return datetime.datetime.now(pytz.utc)
def dt_pack(dt):
    if dt:
        return dt.astimezone(pytz.utc).replace(tzinfo=None)
def dt_unpack(dt):
    if dt:
        return pytz.utc.localize(dt)
def dt_aslocal(dt):
    return dt.astimezone(localtime)
def dt_fromlocal(dt):
    if dt.tzinfo:
        return dt.astimezone(pytz.utc)
    return localtime.localize(dt, is_dst=False).astimezone(pytz.utc)

csrf = CSRF(app)

class cached_property:
    def __init__(self, getter):
        self.getter=getter
    def __get__(self, obj, cls):
        if obj is None: return self
        value = obj.__dict__[self.getter.__name__] = self.getter(obj)
        return value

class ItemNotFound(NotFound):
    pass

####################
#### AUTH
auth = Auth(app)

@app.route('/_auth_cbk')
def auth_callback():
    res = auth.finish_auth() # (True, 2) or (False, "reason")
    if res[0]:
        n = request.args.get('_login_next')
        if n:
            return redirect(n)
        return redirect(url_for('index'))
    flash('Login failed: '+str(res[1]))
    return redirect(url_for('login'))

@app.before_request
def check_login():
    authlvl = auth.check()
    g.authlvl = authlvl
    session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(days=30)
    if authlvl == 0:
        if request.endpoint not in ('login', 'static', 'favicon', 'auth_callback'):
            return redirect(url_for('login', next=request.full_path))

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        csrf.check()
        n = request.args.get('next')
        if n and n[0] == '/':
            session['_login_next'] = n
        return auth.start_auth()
    if g.authlvl > 0:
        return redirect(url_for('index'))
    return render_template('login.html', login_button_url=auth.button_url())

@app.route('/logout', methods=('GET', 'POST'))
def logout():
    if request.method == 'POST':
        csrf.check()
        return auth.logout()
    return Markup('logout?<br><form method=post>')+csrf.generate_csrf_input()+Markup('<input type=submit></form>')

####################
#### DATABASE

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        db.execute("PRAGMA foreign_keys = 1;")
        db.row_factory = sqlite3.Row
        g._database = db
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@attr.s
class File:
    id = attr.ib()
    task = attr.ib()
    filename = attr.ib()
    desc = attr.ib()
    size = attr.ib()
    _url = None
    _length = None
    _format = None
    @classmethod
    def from_id(cls, id):
        row = query_db(
            'select task, filename, desc, length(data) as "size" from files where id = ?',
            (id,), one=True
        )
        if row is None:
            raise ItemNotFound()
        return cls(id=id, **row)
    @classmethod
    def from_task_id(cls, taskid):
        rows = query_db(
            'select id, task, filename, desc, length(data) as "size" from files where task = ?',
            (taskid,)
        )
        return [cls(**row) for row in rows]
    @cached_property
    def url(self):
        return url_for('file_view', id=self.id)
    @cached_property
    def format(self):
        return fileformats.pick_format(self.filename)
    def get_data(self):
        d = query_db(
            'select data from files where id = ?',
            (self.id,), one=True
        )
        return d[0]

@attr.s
class Embed:
    id = attr.ib()
    task = attr.ib()
    type = attr.ib()
    desc = attr.ib()
    data = attr.ib()
    @classmethod
    def from_id(cls, id):
        row = query_db(
            'select task, type, desc, data from embeds where id = ?',
            (id,), one=True
        )
        if row is None:
            raise ItemNotFound()
        return cls(id=id, **row)
    @classmethod
    def from_task_id(cls, taskid):
        rows = query_db(
            'select id, task, type, desc, data from embeds where task = ?',
            (taskid,)
        )
        return [cls(**row) for row in rows]

@attr.s
class Task:
    id = attr.ib()
    ts = attr.ib()
    done = attr.ib()
    title = attr.ib()
    desc = attr.ib()
    deadline = attr.ib()
    embed_count = attr.ib()
    file_count = attr.ib()
    dep_parent_count = attr.ib() # count of tasks this task is dependent on
    dep_parent_notdone_count = attr.ib() # count of not done tasks this task is dependent on
    dep_child_count = attr.ib() # count of tasks that depend on this task
    _embeds = None
    _files = None
    @classmethod
    def from_id(cls, id):
        row = query_db(
            'select ts as "ts [timestamp]", done, title, desc, deadline as "deadline [timestamp]" '
            'from tasks where id = ?',
            (id,), one=True
        )
        if row is None:
            raise ItemNotFound()
        ec = query_db(
            'select count(*) from embeds where task = ?',
            (id,), one=True
        )[0]
        fc = query_db(
            'select count(*) from files where task = ?',
            (id,), one=True
        )[0]
        pc = query_db(
            'select count(*) from dependencies where child = ?',
            (id,), one=True
        )[0]
        pnc = query_db(
            'select count(*) from dependencies d join tasks t on d.parent = t.id where d.child = ? and not t.done',
            (id,), one=True
        )[0]
        cc = query_db(
            'select count(*) from dependencies where parent = ?',
            (id,), one=True
        )[0]
        c = cls(id=id, embed_count=ec, file_count=fc, dep_parent_count=pc, dep_parent_notdone_count=pnc, dep_child_count=cc, **row)
        c.ts = dt_unpack(c.ts)
        c.deadline = dt_unpack(c.deadline)
        if g.authlvl < 2:
            if (dt_now()- c.ts).total_seconds() > 86400:
                c.title = row['title'][:6]+'...'
                c.desc = '[guest mode hidden]'
        return c
    @classmethod
    def from_sql(cls, sql, args=(), only=True):
        '''
        executes sql, interprets first column of rows to be task ids and converts that
        only=True:
            'select id from tasks...' => [Task(id=1), Task(id=2), ...]
        only=False:
            'select id, count(thing)...' => [(Task(id=1), 3), (Task(id=2), 1), ...]
        '''
        rows = query_db(sql, args=args)
        if only:
            return [cls.from_id(row[0]) for row in rows]
        return [(cls.from_id(row[0]), *row[1:]) for row in rows]
    @cached_property
    def embeds(self):
        return Embed.from_task_id(self.id)
    @cached_property
    def files(self):
        return File.from_task_id(self.id)
    @cached_property
    def dep_parents(self):
        pids = query_db('select parent from dependencies where child = ?', (self.id,))
        return [Task.from_id(pid[0]) for pid in pids]
    @cached_property
    def dep_children(self):
        cids = query_db('select child from dependencies where parent = ?', (self.id,))
        return [Task.from_id(cid[0]) for cid in cids]

####################
#### INDEX

@app.route('/')
def index():
    newest = Task.from_sql('select id from tasks order by datetime(ts) desc limit 10')
    dead = Task.from_sql('select id from tasks where not done and strftime("%s","now") > strftime("%s", deadline) order by deadline asc limit 10')
    soon = Task.from_sql('select id from tasks where not done and (strftime("%s", deadline) - strftime("%s","now")) between 0 and 86400 order by deadline asc limit 10')
    approaching = Task.from_sql('select id from tasks where not done and (strftime("%s", deadline) - strftime("%s","now")) > 86400 order by deadline asc limit 10')
    doable = Task.from_sql('''\
        select t.id
        from tasks t
            left join (
                select d.child as c
                from dependencies d
                join tasks p
                    on d.parent = p.id
                where not p.done
            ) on t.id = c
        where not t.done
        group by t.id
        having count(c) = 0
        order by datetime(t.ts) desc limit 10
        ''')
    most_deps = Task.from_sql('''\
        select t.id, count(p)
        from tasks t
            left join (
                select d.parent as p
                from dependencies d
                join tasks c
                    on d.child = c.id
                where not c.done
            ) on t.id = p
        where not t.done
        group by t.id
        having count(p) > 0
        order by count(p) desc
        limit 10
        ''', only=False)
    recomm = Task.from_sql('select id from tasks where not done order by random() limit 5')
    stats = {
        'done': query_db('select count(*) from tasks where done = 1', one=True)[0],
        'not': query_db('select count(*) from tasks where done = 0 and ((deadline is NULL) or (strftime("%s","now") <= strftime("%s", deadline)))', one=True)[0],
        'dead': query_db('select count(*) from tasks where done = 0 and (strftime("%s","now") > strftime("%s", deadline))', one=True)[0],
        'fail': query_db('select count(*) from tasks where done = 2', one=True)[0],
        'all': query_db('select count(*) from tasks', one=True)[0],
    }
    return render_template(
        'index.html',
        newest=newest,
        dead=dead,
        soon=soon,
        approaching=approaching,
        doable=doable,
        most_deps=most_deps,
        stats=stats,
        recomm=recomm
    )

class TaskParseException(Exception):
    pass


human_deadline_regex = re.compile(r'(?P<num>([0-9]*.)?[0-9])\s*(?P<unit>[a-z]+)')
def parse_deadline(form):
    has = form.get('has_deadline', '')
    raw_ts = form.get('d_ts_d', ''), form.get('d_ts_t')
    raw_in = form.get('d_in', '')
    now = dt_now()
    if has == 'no':
        return None
    if has == 'ts':
        try:
            dt = dt_fromlocal(datetime.datetime.strptime(
                '{} {}'.format(*raw_ts),
                '%Y-%m-%d %H:%M'
            ))
        except (ValueError, OverflowError):
            raise TaskParseException('invalid deadline timestamp')
        return dt
    if has == 'in':
        m = human_deadline_regex.search(raw_in)
        if not m:
            raise TaskParseException('invalid human delta (deadline in)')
        try:
            num = float(m.group('num'))
        except (ValueError, OverflowError):
            raise TaskParseException('invalid number in human delta (deadline in)')
        unit = m.group('unit')
        if (len(unit) > 1) and unit[-1] == 's': # crop away plural
            unit = unit[:-1]
        if unit in ('year', 'y', 'yr'):
            return now + datetime.timedelta(days=365*num)
        if unit in ('month', 'mth', 'mon', 'm'):
            return now + datetime.timedelta(days=30*num)
        if unit in ('week', 'wk', 'w'):
            return now + datetime.timedelta(weeks=num)
        if unit in ('day', 'd'):
            return now + datetime.timedelta(days=num)
        if unit in ('hour', 'hr', 'h'):
            return now + datetime.timedelta(hours=num)
        if unit in ('minute', 'min'): # m is months
            return now + datetime.timedelta(minutes=num)
        if unit in ('second', 'sec', 's'):
            return now + datetime.timedelta(seconds=num)
        raise TaskParseException('unknown unit in human delta (deadline in)')
    raise TaskParseException('no deadline format chosen (?!)')

@app.route('/task/new', methods=('GET', 'POST'))
def task_new():
    if request.method == 'POST':
        csrf.check()
        try:
            title = request.form.get('title', '')
            if not (0 < len(title) <= 40):
                raise TaskParseException('title too long or short')
            desc = request.form.get('desc', '')
            deadline = parse_deadline(request.form)
            files = []
            for i in range(3):
                if request.form.get('file{}_has'.format(i)) == 'on':
                    fdesc = request.form.get('file{}_desc'.format(i), '')
                    fobj = request.files.get('file'+str(i))
                    if fobj.filename == '':
                        raise TaskParseException('file #{} enabled but not attached'.format(i))
                    fname = fobj.filename
                    fstr = fobj.stream
                    files.append((fdesc, fname, fstr))
            embeds = []
            for i in range(3):
                if request.form.get('embed{}_has'.format(i)) == 'on':
                    edesc = request.form.get('embed{}_desc'.format(i), '')
                    eurl = request.form.get('embed'+str(i))
                    if not eurl:
                        raise TaskParseException('embed #{} enabled but not provided'.format(i))
                    # TODO: embedformats.choose(eurl), raise "embed invalid"
                    embeds.append([edesc, eurl])
            # fully validated here, start saving
            db = get_db()
            c = db.cursor() # i hope a fresh cursor wont have an old lastrowid
            c.execute(
                'insert into tasks (title, desc, deadline) values (?,?,?)',
                (title, desc, dt_pack(deadline))
            )
            new_id = c.lastrowid
            if not new_id:
                # this shouldnt happen but to be sure
                db.rollback()
                raise TaskParseException('no lastrowid after creating task!')
            for f in files:
                c.execute(
                    'insert into files (task, filename, desc, data) values (?,?,?,?)',
                    (new_id, f[1], f[0], f[2].read())
                )
            for e in embeds:
                c.execute(
                    'insert into embeds (task, type, desc, data) values (?,?,?,?)',
                    (new_id, 'url', e[0], e[1]) # FIXME: 'url'
                )
            # if nothing excepted before here we should be good right??
            db.commit()
            return redirect(url_for('task', id=new_id))

        except TaskParseException as e:
            flash('An error occured while processing the task: "'+e.args[0]+'". Remember to reattach your files!!!')
    return render_template('task_new.html')

@app.route('/task/<int:id>')
def task(id):
    task = Task.from_id(id)
    return render_template('task.html', task=task)

@app.route('/task/<int:id>/done', methods=('GET', 'POST'))
def task_done(id):
    if request.method == 'POST':
        csrf.check()
        done = request.form.get('done')
        db = get_db()
        if done == 'yes':
            db.execute('update tasks set done = 1 where id = ?', (id,))
        elif done == 'no':
            db.execute('update tasks set done = 0 where id = ?', (id,))
        elif done == 'fail':
            db.execute('update tasks set done = 2 where id = ?', (id,))
        else:
            flash('invalid done status chosen')
            return redirect(request.full_path) # keeps the ?next
        db.commit()
        if request.args.get('next'):
            return redirect(request.args.get('next'))
        return redirect(url_for('task', id=id))
    task = Task.from_id(id)
    return render_template('task_done.html', task=task)

@app.route('/task/<int:id>/edit', methods=('GET', 'POST'))
def task_edit(id):
    if request.method == 'POST':
        csrf.check()
        title = request.form.get('title', '')
        if 0 < len(title) <= 40:
            desc = request.form.get('desc', '')
            db = get_db()
            db.execute('update tasks set title = ?, desc = ? where id = ?', (title, desc, id))
            db.commit()
            return redirect(url_for('task', id=id))
        flash('title too long or short!')
    task = Task.from_id(id)
    return render_template('task_edit.html', task=task)

@app.route('/task/<int:id>/deadline', methods=('GET', 'POST'))
def task_deadline(id):
    if request.method == 'POST':
        csrf.check()
        try:
            deadline = parse_deadline(request.form)
            db = get_db()
            db.execute('update tasks set deadline = ? where id = ?', (dt_pack(deadline), id))
            db.commit()
            return redirect(url_for('task', id=id))
        except TaskParseException as e:
            flash('Invalid deadline settings: "'+e.args[0])
    task = Task.from_id(id)
    return render_template('task_deadline.html', task=task)

@app.route('/task/<int:id>/depend', methods=('GET', 'POST'))
def task_depend(id):
    fs, selection = fsess.read()
    if selection is None:
        fs = fsess.create(b'started')
        return redirect(url_for('task_depend', id=id, framesess=fs))
    task = Task.from_id(id)
    if request.method == 'POST':
        csrf.check()
        if selection != b'started':
            selection = int(selection.decode())
            Task.from_id(selection)
            db = get_db()
            db.execute('insert into dependencies (parent, child) values (?,?)', (selection, id))
            db.commit()
            return redirect(url_for('task', id=id))
        flash('please select a task')
    return render_template('task_depend.html', task=task, framesess=fs)

@app.route('/task/<int:id>/upload', methods=('GET', 'POST'))
def task_upload(id):
    task = Task.from_id(id)
    if request.method == 'POST':
        csrf.check()
        print(request.form, request.files)
        try:
            files = []
            for i in range(3):
                if request.form.get('file{}_has'.format(i)) == 'on':
                    fdesc = request.form.get('file{}_desc'.format(i), '')
                    fobj = request.files.get('file'+str(i))
                    if fobj.filename == '':
                        raise TaskParseException('file #{} enabled but not attached'.format(i))
                    fname = fobj.filename
                    fstr = fobj.stream
                    files.append((fdesc, fname, fstr))
            db = get_db()
            c = db.cursor()
            for f in files:
                c.execute(
                    'insert into files (task, filename, desc, data) values (?,?,?,?)',
                    (id, f[1], f[0], f[2].read())
                )
            db.commit()
            return redirect(url_for('task', id=id))
        except TaskParseException as e:
            flash('An error occured while processing the upload: "'+e.args[0]+'". Remember to reattach your files!!!')
    return render_template('task_upload.html', task=task)


@app.route('/file/<int:id>/view')
def file_view(id):
    if g.authlvl < 2:
        abort(403)
    f = File.from_id(id)
    resp = make_response(f.get_data())
    resp.headers['Content-Disposition'] = \
        'inline; filename="{}"'.format(f.filename.replace('"', "\""))
    resp.headers['Content-Type'] = f.format.mimetype
    return resp

@app.route('/file/<int:id>/edit', methods=('GET', 'POST'))
def file_edit(id):
    f = File.from_id(id)
    if request.method == 'POST':
        csrf.check()
        desc = request.form.get('desc', '')
        db = get_db()
        db.execute('update files set desc = ? where id = ?', (desc, id))
        db.commit()
        return redirect(url_for('task', id=f.task))
    return render_template('file_edit.html', f=f, task=Task.from_id(f.task))

@app.route('/file/<int:id>/delete', methods=('GET', 'POST'))
def file_delete(id):
    f = File.from_id(id)
    if request.method == 'POST':
        csrf.check()
        if request.form.get('yes_i_am') == 'on':
            db = get_db()
            db.execute('delete from files where id = ?', (id,))
            db.commit()
            flash('File deleted!')
        return redirect(url_for('task', id=f.task))
    return render_template('file_delete.html', file=f, task=Task.from_id(f.task))


@app.route('/random')
def random():
    id = query_db('select id from tasks where not done order by RANDOM() limit 1', one=True)
    if not id:
        return 'No tasks!'
    return redirect(url_for('task', id=id[0]))

TASKS_PER_PAGE = 20
def filter_parse():
    def a(par, args, default='_'):
        p = request.args.get(par)
        if p not in args:
            return default
        return p
    done = a('done', ['y', 'n', 'f', 'd'])
    dead = a('dead', ['u', 'f', 'p', 'c'])
    deadp = ''
    if dead == 'c':
        deadp = request.args.get('deadp')
        # todo: verify regex
    fe = a('fe', ['nn', 'yn', 'ny', 'yy', 'c'])
    fep = ''
    if fe == 'c':
        fep = request.args.get('fep')
        # todo: as above
    dep = a('dep', ['hap', 'hup', 'hdp', 'hac', 'huc'])
    sort = a('sort', ['cd', 'ca', 'dd', 'dc'], 'cd')
    page = 1
    try:
        page = int(request.args.get('page'))
    except:
        pass
    return dict(done=done, dead=dead, deadp=deadp, fe=fe, fep=fep, dep=dep, sort=sort, page=page)

def filter_query(query):
    joins = []
    group = False
    having = []
    where = []
    order = ''
    # dependency querying
    if query['dep'] != '_':
        group = True
        if query['dep'] == 'hap':
            joins.append('join dependencies d on d.parent = t.id')
        if query['dep'] == 'hup':
            joins.append('''\
                join (
                    select d.parent as p
                    from dependencies d
                    join tasks c
                        on c.id = d.child
                    where not c.done
                ) on t.id = p
            ''')
        if query['dep'] == 'hdp':
            joins.append('''\
                left join (
                    select d.parent as p
                    from dependencies d
                    join tasks c
                        on c.id = d.child
                    where not c.done
                ) on t.id = p
            ''')
            having.append('count(p) = 0')
    # done
    if query['done'] == 'y':
        where.append('t.done = 1')
    elif query['done'] == 'n':
        where.append('t.done != 1')
    elif query['done'] == 'f':
        where.append('t.done = 2')
    elif query['done'] == 'd':
        where.append('t.done = 0')
    # deadline
    if query['dead'] == 'u':
        where.append('t.deadline is NULL')
    elif query['dead'] == 'f':
        where.append('datetime(t.deadline) > datetime("now")')
    elif query['dead'] == 'p':
        where.append('datetime(t.deadline) < datetime("now")')
    elif query['dead'] == 'c':
        where.append('TODO(DEADLINE)')
    # files&embeds
    if query['fe'] != '_':
        if query['fe'] == 'c':
            where.append('TODO(FE)')
        else:
            files = query['fe'][0] == 'y'
            embeds = query['fe'][1] == 'y'
            joins.append('left join files f on f.task = t.id')
            having.append('count(f.id) {} 0'.format('>' if files else '='))
            group = True
            joins.append('left join embeds e on e.task = t.id')
            having.append('count(e.id) {} 0'.format('>' if embeds else '='))
            group = True
    # sorting
    if query['sort'][0] == 'd':
        # dependency sorting
        group = True
        if query['sort'] == 'dd':
            joins.append('''\
                join (
                    select sd.parent as sdp
                    from dependencies sd
                    join tasks c
                        on sd.child = c.id
                    where not c.done
                ) on t.id = sdp
            ''')
            order = 'order by count(sdp) desc'
        else:
            joins.append('left join dependencies sd on sd.child = t.id')
            order = 'order by count(sd.parent) desc'
    else:
        order = 'order by t.ts '
        if query['sort'][1] == 'd':
            order += 'desc'
        else:
            order += 'asc'
    limit = TASKS_PER_PAGE+1
    offset = (query['page']-1)*TASKS_PER_PAGE
    ## build the thing
    q = 'select t.id from tasks t\n'
    q += '\n'.join(joins)
    if where:
        q += '\nwhere ('
        q += ')\n  and ('.join(where)
        q += ') '
    if group:
        q += '\ngroup by t.id '
        if having:
            q += '\nhaving ('
            q += ')\n  and ('.join(having)
            q += ') '
    q += '\n{}\nlimit {} offset {}'.format(order, limit, offset)
    #print('\033[33m'+q+'\033[0m')
    return Task.from_sql(q)


@app.route('/filter')
def filter():
    query = filter_parse()
    canonical = url_for('filter', **query)
    if request.full_path != canonical:
        return redirect(canonical)
    results = filter_query(query)
    np = None
    if len(results) == TASKS_PER_PAGE+1:
        results = results[:TASKS_PER_PAGE]
        nq = query.copy()
        nq['page'] += 1
        np = url_for('filter', **nq)
    pp = None
    if query['page'] > 1:
        pq = query.copy()
        pq['page'] -= 1
        pp = url_for('filter', **pq)
    return render_template('filter.html', query=query, results=results, np=np, pp=pp)

def search_parse():
    def a(par, args, default='_'):
        p = request.args.get(par)
        if p not in args:
            return default
        return p
    desc = a('desc', ['on'])
    st = a('st', ['w', 'l'], 'w')
    qw, ql = '', ''
    if st == 'w':
        qw = request.args.get('qw', '')
    else:
        ql = request.args.get('ql', '')
    page = 1
    try:
        page = int(request.args.get('page'))
    except:
        pass
    return dict(st=st, qw=qw, ql=ql, desc=desc, page=page)

def search_query(query):
    like = []
    if query['st'] == 'w':
        for word in query['qw'].split(' '):
            word = word.strip()
            if len(word) > 1:
                like.append('%'+word+'%')
    else:
        if len(query['ql']) > 1:
            like.append(query['ql'])
    if not like:
        return []
    limit = TASKS_PER_PAGE+1
    offset = (query['page']-1)*TASKS_PER_PAGE
    q = 'select t.id from tasks t where\n'
    if query['desc']:
        q += ' and '.join(['(t.title like ? or t.desc like ?)'] * len(like))
        nl = []
        for l in like:
            nl.append(l)
            nl.append(l)
        like = nl
    else:
        q += ' and '.join(['t.title like ?'] * len(like))
    q += '\norder by datetime(t.ts)\nlimit {} offset {}'.format(limit, offset)
    #print('\033[33m'+q+'\033[0m')
    return Task.from_sql(q, like)

@app.route('/search')
def search():
    query = search_parse()
    canonical = url_for('search', **query)
    if request.full_path != canonical:
        return redirect(canonical)
    results = search_query(query)
    np = None
    if len(results) == TASKS_PER_PAGE+1:
        results = results[:TASKS_PER_PAGE]
        nq = query.copy()
        nq['page'] += 1
        np = url_for('search', **nq)
    pp = None
    if query['page'] > 1:
        pq = query.copy()
        pq['page'] -= 1
        pp = url_for('search', **pq)
    return render_template('search.html', query=query, results=results, np=np, pp=pp)

@app.route('/_frame/search/')
def search_frame():
    fs, _ = fsess.read()
    if fs is None:
        return '[ERR] no frame session', 404
    query = search_parse()
    query['framesess'] = fs
    canonical = url_for('search_frame', **query)
    if request.full_path != canonical:
        return redirect(canonical)
    results = search_query(query)
    np = None
    if len(results) == TASKS_PER_PAGE+1:
        results = results[:TASKS_PER_PAGE]
        nq = query.copy()
        nq['page'] += 1
        np = url_for('search_frame', **nq)
    pp = None
    if query['page'] > 1:
        pq = query.copy()
        pq['page'] -= 1
        pp = url_for('search_frame', **pq)
    def search_builder(taskid):
        return url_for('search_frame_pick', id=taskid, framesess=fs, back=request.full_path)
    return render_template('search_frame.html', query=query, pp=pp, np=np, results=results, search_builder=search_builder)

@app.route('/_frame/search/<int:id>')
def search_frame_pick(id):
    fs, _ = fsess.read()
    if fs is None:
        return '[ERR] no frame session', 404
    task = Task.from_id(id)
    fsess.write(str(id).encode())
    return render_template('search_frame_pick.html', task=task, back=request.args.get('back', '/'))

@app.route('/_frame/time')
def time_frame():
    fs, _ = fsess.read()
    if fs is None:
        return '[ERR] no frame session', 404
    hour = request.args.get('h', 12)
    minute = request.args.get('m', 00)
    return render_template('time_frame.html')

@app.route('/favicon.ico')
def favicon():
    return send_file('static/favicon.png', as_attachment=False, mimetype='image/png')

####################
#### ERROR HANDLING
@app.errorhandler(404)
def e404(*args):
    return render_template('err/404.html')

####################
#### JINJA

def make_icon(name, classes='', hover=''):
    if classes is None: classes = ''
    if hover is None: hover = ''
    return Markup('<span class="silkicon silk_{} {}" title="{}"></span>').format(name, classes, hover)

app.jinja_env.globals['ndk_domain'] = app.config['SERVER_NAME']
app.jinja_env.globals['ndk_version'] = subprocess.check_output(['git', 'describe', '--always']).decode().strip()
app.jinja_env.globals['make_icon'] = make_icon

def humandelta(seconds):
    i = int(seconds // 31536000)
    if i > 1:
        return '{} years'.format(i)
    i = int(seconds // 2592000)
    if i > 1:
        return '{} months'.format(i)
    i = int(seconds // 86400)
    if i > 1:
        return '{} days'.format(i)
    i = int(seconds // 3600)
    if i > 1:
        return '{} hours'.format(i)
    i = int(seconds // 60)
    if i > 1:
        return '{} minutes'.format(i)
    return '{} seconds'.format(int(seconds))

@app.template_filter('humandelta')
def humandelta_filter(x):
    if isinstance(x, datetime.timedelta):
        return humandelta_filter(x.total_seconds())
    if isinstance(x, datetime.datetime):
        return humandelta_filter(dt_now() - x)
    if -1 < x < 1:
        return 'now'
    if x > 0:
        return humandelta(abs(x)) + ' ago'
    return 'in ' + humandelta(abs(x))

@app.template_filter('datetime')
def datetime_filter(x):
    return x.astimezone(localtime).strftime("%Y-%m-%d %H:%M")

@app.template_filter('datetimeprecise')
def datetime_filter(x):
    return x.astimezone(localtime).strftime("%Y-%m-%d %H:%M:%S %Z")
