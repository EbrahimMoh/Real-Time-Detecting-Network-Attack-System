from flask import Flask, render_template
import subprocess

app = Flask(__name__)

scripts = {
    'ftp-port': 'ftp-port.py',
    'ssh-port': 'ssh-port.py',
    'sql_injection': 'sql_injection.py',
    'scanning_ports': 'scanning_ports.py',
}


script_running = {script_name: False for script_name in scripts}

@app.route('/')
def index():
    return render_template('index.html', scripts=scripts, script_running=script_running)

@app.route('/run/<script_name>')
def run_script(script_name):
    script_path = scripts.get(script_name)
    if script_path:
        subprocess.Popen(['python3', script_path])
        script_running[script_name] = True
        return f'Started {script_name}'
    else:
        return 'Script not found'

@app.route('/stop/<script_name>')
def stop_script(script_name):
  
    script_running[script_name] = False
    return f'Stopped {script_name}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)