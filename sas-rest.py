#!flask/bin/python
from logging import debug
from flask import Flask, jsonify, request, make_response, Response, abort
import pandas as pd
import json
import base64
# import sqlite3
import ldap
import datetime
from pathlib import Path

# https://facelessuser.github.io/wcmatch/glob/#globmatch
from wcmatch import glob

from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

# Кому можно пользоваться сервисом
# Внимание,используем только строчные буквы в именах пользователей!
white_list = [
    'ddmitry@mycompany.localdomain',
]

# Правва доступа пользователей к папкам. Словарь списков. Ключ - полное имя пользователя в
# формате 'username@mycompany.localdomain', значение - список строк, содержащий пути доступа.
# Путь указывать от корня ФС. Допустимы симовлы
# *	Matches everything except slashes. On Windows it will avoid matching backslashes as well as slashes.
# **	Matches zero or more directories, but will never match the directories . and ... Requires the GLOBSTAR flag.
folder_restrictions = {
    'ddmitry@mycompany.localdomain' : ['/sas/**/*.sas7bdat', '/**/db/**/*.sas7bdat'],
}

# Если установлено в True, реальных обращений к серверу каталога не происходит
ldap_no_validation = True

def check_path_restrictions(user, path:Path):
    """Проверяем права доступа пользователя к запрошенному файлу. Возвращаем True, если разрешено."""
    user = user.lower()
    full_path = path.resolve()
    try:
        path_list = folder_restrictions[user]
    except KeyError:
        path_list = ''
    print('Given full path', full_path)
    print(f'Allowed paths for user {user}: {path_list}')
    for path_item in path_list:
        if glob.globmatch(full_path, path_item, flags=glob.GLOBSTAR):
            print(f'Match path "{path_item}"')
            return True
    print('Path doesn''t match!')
    return False


def check_ldap(user, password):
    """"Проверяем наличие пользователя в LDAP. Если есть - возвращаем имя пользователя, иначе None"""
    if ldap_no_validation:
        print(f"LDAP no_validation mode enabled, user='{user}'")
        return True
    user = user.lower()
    ldap_server = "ldap://dc.mycompany.localdomain"
    ldap.set_option(ldap.OPT_REFERRALS, 0)
    ldap.protocol_version = 3
    conn = ldap.initialize(ldap_server)
    try:
        conn.simple_bind_s(user, password)
        # print('password Ok!')
        if white_list.count(user):
            print(f"User '{user}' in allowed")
            return user
        print(f"User '{user}' in not in white_list")
    except ldap.INVALID_CREDENTIALS:
        print('Wrong username or password')
    return None


@auth.verify_password
def verify_password(username, password):
    # print(f'username, password: {username}, {password}')
    return check_ldap(username, password)


@auth.error_handler
def unathorized():
    return make_response(jsonify({'error':'Unathorized access'}), 401)
    # return make_response(jsonify({'error':'Unathorized access'}), 403) # Некорректно, но так проще отлаживать


def get_sas_table(table_path, enc='iso-8859-5'):
    """Возвращает объект pandas dataframe, прочитав sas7bdat таблицу по указанному пути"""
    df = pd.read_sas(table_path, encoding=enc)


def get_sas_table_iter(table_path, enc='iso-8859-5', chunksize=100000):
    """Возвращает итератор объекта pandas dataframe, читающий таблицу sas7bdat по указанному пути"""
    df_iter = pd.read_sas(table_path, encoding=enc, chunksize=chunksize, iterator=True)
    return df_iter


@app.route('/api/v1.0/tables', methods=['GET'])
@auth.login_required
def tables_get():
    chunksize=100000  # Размер одного чанка
    print('-------------------------------------------')
    print('args=', request.args)
    # Имя (путь) к таблице
    table_path = request.args.get('file')
    # Вид вывода (json/csv)
    out_type = request.args.get('format')
    if out_type != 'json':
        out_type = 'csv'
    print('out_type =', out_type)
    # Чтение данных с диска
    table_path = Path(table_path)
    # Проверка прав доступа к файлу с данными
    if check_path_restrictions(auth.current_user(), table_path)==False:
        abort(403)
    # Проверяю путь на существование
    print('Started reading table at:', datetime.datetime.now())
    if out_type=='json':
        df = get_sas_table(table_path)
        print(df.info(verbose=False, memory_usage='deep'))
        print('Finishing reading table at:', datetime.datetime.now())
        result = df.to_json(orient='records', force_ascii=False)
        return Response(result, mimetype='application/json')
    if out_type=='csv':
        iter_count = 0
        start_time = datetime.datetime.now()
        iter_time = start_time
        df_iter = get_sas_table_iter(table_path, chunksize=chunksize)
        def generate():
            for df in df_iter:
                nonlocal iter_count, iter_time
                current_time = datetime.datetime.now()
                if (current_time-iter_time).total_seconds()>60:
                    iter_time = current_time
                iter_count += 1
                header = False
                if iter_count==1:
                    header = True
                result = df.to_csv(index=False, header=header)
                yield result
            print(f'Table procedded during: {current_time-start_time}')
        return Response(generate(), mimetype='test/csv')


# if __name__=='__main__':
#     app.run(threaded=True, debug=True)

        