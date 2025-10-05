from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from spellchecker import SpellChecker

import sqlite3
import os
import uuid
import json
from datetime import datetime
import re
from functools import wraps

# Add these imports at the top of the file
import zipfile
import shutil
import datetime
import os.path
import io

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production



##############################
# Configuration
UPLOAD_FOLDER = 'uploads/documents' # where files should be stored (imagination)
ALLOWED_EXTENSIONS = {'txt', 'csv'}
DATABASE = 'database.db'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER # flask ko bta rhe hen yahi save krni ha file
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Helper functions
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  #initialize
    return conn

def init_db():
    conn = get_db_connection()
    with open('schema.sql') as f:
        conn.executescript(f.read())
    
    # Create admin user if it doesn't exist
    admin_exists = conn.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin_exists:
        conn.execute(
            'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
            ('admin', 'admin@example.com', generate_password_hash('admin123'), 1)
        )
        conn.commit()
    
    conn.close()

def allowed_file(filename): ## 
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Authentication decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        
        conn = get_db_connection()
        user = conn.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        
        if not user or not user['is_admin']:
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function

# Custom Jinja2 filter for highlighting search terms
@app.template_filter('highlight_search_terms')
def highlight_search_terms(text, terms):
    if not text or not terms:
        return text
    
    import re
    
    result = text
    for term in terms:
        if not term:
            continue
        
        pattern = re.compile(f'({re.escape(term)})', re.IGNORECASE)
        result = pattern.sub(r'<mark>\1</mark>', result)
    
    return result

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return render_template('search_results.html', results=[], query='')
    
    # Tokenize the query
    words = re.sub(r'[^\w\s]', ' ', query.lower()).split()
    
    # Remove common stop words
    stop_words = {'a', 'an', 'the', 'and', 'or', 'but', 'is', 'are', 'was', 'were'}
    words = [word for word in words if word and word not in stop_words]
    
    if not words:
        return render_template('search_results.html', results=[], query=query)
    
    # Search the index
    conn = get_db_connection()
    placeholders = ' OR '.join(['word = ?' for _ in words])
    query_sql = f'''
        SELECT di.document_id, d.filename, d.original_filename, SUM(di.frequency) as relevance, 
               d.upload_date, u.username
        FROM document_index di
        JOIN documents d ON di.document_id = d.id
        LEFT JOIN users u ON d.user_id = u.id
        WHERE {placeholders}
        GROUP BY di.document_id
        ORDER BY relevance DESC
    '''
    
    results = conn.execute(query_sql, words).fetchall()
    
    # Get snippets for each result
    results_with_snippets = []
    for result in results:
        snippet = None
        for word in words:
            positions_data = conn.execute(
                'SELECT positions FROM document_index WHERE document_id = ? AND word = ?',
                (result['document_id'], word)
            ).fetchone()
            
            if positions_data and positions_data['positions']:
                positions = json.loads(positions_data['positions'])
                if positions:
                    # Read document content
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], result['filename'])
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Create snippet
                        all_words = content.split()
                        position = positions[0]
                        snippet_length = 30  # words
                        start = max(0, position - snippet_length // 2)
                        end = min(len(all_words), start + snippet_length)
                        snippet = ' '.join(all_words[start:end])
                        break
                    except Exception as e:
                        print(f"Error reading file: {e}")
        
        results_with_snippets.append({
            'id': result['document_id'],
            'filename': result['filename'],
            'original_filename': result['original_filename'],
            'relevance': result['relevance'],
            'upload_date': result['upload_date'],
            'username': result['username'],
            'snippet': snippet
        })
    
    conn.close()
    return render_template('search_results.html', results=results_with_snippets, query=query)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('index')
                
            flash('Login successful!', 'success')
            return redirect(next_page)
        
        flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        conn = get_db_connection()
        
        # Check if username or email already exists
        existing_user = conn.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?', 
            (username, email)
        ).fetchone()
        
        if existing_user:
            conn.close()
            flash('Username or email already exists', 'error')
            return render_template('register.html')
        
        # Create new user
        conn.execute(
            'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
            (username, email, generate_password_hash(password), 0)
        )
        conn.commit()
        
        user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        
        # Log in the new user
        session.clear()
        session['user_id'] = user_id
        session['username'] = username
        session['is_admin'] = False
        
        flash('Registration successful!', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/my-documents')
@login_required
def my_documents():
    conn = get_db_connection()
    documents = conn.execute(
        'SELECT * FROM documents WHERE user_id = ? ORDER BY upload_date DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    
    return render_template('my-documents.html', documents=documents)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'})
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'})
        
        if file and allowed_file(file.filename):
            # Generate unique filename
            original_filename = secure_filename(file.filename)
            file_extension = os.path.splitext(original_filename)[1]
            unique_filename = f"{uuid.uuid4()}{file_extension}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Save the file
            file.save(file_path)
            
            # Add to database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO documents (filename, original_filename, user_id) VALUES (?, ?, ?)',
                (unique_filename, original_filename, session['user_id'])
            )
            document_id = cursor.lastrowid
            
            # Index the document
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Tokenize the content
                words = re.sub(r'[^\w\s]', ' ', content.lower()).split()
                
                # Remove stop words
                stop_words = {'a', 'an', 'the', 'and', 'or', 'but', 'is', 'are', 'was', 'were', 'be', 'been', 'being'}
                filtered_words = [word for word in words if word and word not in stop_words]
                
                # Count word frequencies and positions
                word_map = {}
                for i, word in enumerate(filtered_words):
                    if word not in word_map:
                        word_map[word] = {'count': 0, 'positions': []}
                    word_map[word]['count'] += 1
                    word_map[word]['positions'].append(i)
                
                # Add words to the index
                for word, data in word_map.items():
                    conn.execute(
                        '''
                        INSERT INTO document_index (document_id, word, frequency, positions) 
                        VALUES (?, ?, ?, ?)
                        ''',
                        (document_id, word, data['count'], json.dumps(data['positions']))
                    )
                
                conn.commit()
                
                # Get document count for this user
                document_count = conn.execute(
                    'SELECT COUNT(*) FROM documents WHERE user_id = ?',
                    (session['user_id'],)
                ).fetchone()[0]
                
                conn.close()
                
                return jsonify({
                    'success': True, 
                    'documentId': document_id,
                    'filename': original_filename,
                    'documentCount': document_count
                })
                
            except Exception as e:
                conn.close()
                return jsonify({'error': f'Error indexing document: {str(e)}'})
        
        return jsonify({'error': 'Invalid file type'})
    
    return render_template('upload.html')

@app.route('/document/<int:document_id>/view')
def view_document(document_id):
    conn = get_db_connection()
    document = conn.execute('SELECT * FROM documents WHERE id = ?', (document_id,)).fetchone()
    conn.close()
    
    if not document:
        flash('Document not found', 'error')
        return redirect(url_for('index'))
    
    # Check if user has permission to view this document
    # if not session.get('is_admin') and document['user_id'] != session.get('user_id'):
    #     flash('You do not have permission to view this document', 'error')
    #     return redirect(url_for('index'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return render_template('view_document.html', document=document, content=content)
    except Exception as e:
        flash(f'Error reading document: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/document/<int:document_id>/download')
def download_document(document_id):
    conn = get_db_connection()
    document = conn.execute('SELECT * FROM documents WHERE id = ?', (document_id,)).fetchone()
    conn.close()
    
    if not document:
        flash('Document not found', 'error')
        return redirect(url_for('index'))
    
    # Check if user has permission to download this document
    # if not session.get('is_admin') and document['user_id'] != session.get('user_id'):
    #     flash('You do not have permission to download this document', 'error')
    #     return redirect(url_for('index'))
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=document['original_filename']
    )

# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, is_admin, created_at FROM users').fetchall()
    documents = conn.execute('SELECT COUNT(*) as count FROM documents').fetchone()
    
    # Get recent documents with uploader information
    recent_documents = conn.execute('''
        SELECT d.id, d.original_filename, d.upload_date, u.username
        FROM documents d
        JOIN users u ON d.user_id = u.id
        ORDER BY d.upload_date DESC
        LIMIT 5
    ''').fetchall()
    
    conn.close()
    
    return render_template('admin/dashboard.html', users=users, document_count=documents['count'], documents=recent_documents)

@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, email, is_admin, created_at FROM users').fetchall()
    conn.close()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/documents')
@admin_required
def admin_documents():
    conn = get_db_connection()
    documents = conn.execute('''
        SELECT d.id, d.original_filename, d.filename, d.upload_date, u.username
        FROM documents d
        JOIN users u ON d.user_id = u.id
        ORDER BY d.upload_date DESC
    ''').fetchall()
    conn.close()
    
    return render_template('admin/documents.html', documents=documents)

@app.route('/admin/documents/<int:document_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_document(document_id):
    conn = get_db_connection()
    
    # Check if document exists
    document = conn.execute('SELECT * FROM documents WHERE id = ?', (document_id,)).fetchone()
    
    if not document:
        conn.close()
        return jsonify({'success': False, 'error': 'Document not found'})
    
    # Delete document from index
    conn.execute('DELETE FROM document_index WHERE document_id = ?', (document_id,))
    
    # Delete document from database
    conn.execute('DELETE FROM documents WHERE id = ?', (document_id,))
    conn.commit()
    conn.close()
    
    # Delete file from disk
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], document['filename'])
    if os.path.exists(file_path):
        os.remove(file_path)
    
    return jsonify({'success': True})

@app.route('/admin/users/add', methods=['POST'])
@admin_required
def admin_add_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('isAdmin', False)
    
    if not username or not email or not password:
        return jsonify({'success': False, 'error': 'All fields are required'})
    
    conn = get_db_connection()
    
    # Check if username or email already exists
    existing = conn.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    
    if existing:
        conn.close()
        return jsonify({'success': False, 'error': 'Username or email already exists'})
    
    # Create user
    conn.execute(
        'INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)',
        (username, email, generate_password_hash(password), 1 if is_admin else 0)
    )
    conn.commit()
    
    user_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
    conn.close()
    
    return jsonify({'success': True, 'userId': user_id})

@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@admin_required
def admin_update_user(user_id):
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    is_admin = data.get('isAdmin')
    
    conn = get_db_connection()
    
    # Check if user exists
    user = conn.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'})
    
    # Check if username or email already exists
    if username or email:
        existing = conn.execute(
            'SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?',
            (username, email, user_id)
        ).fetchone()
        
        if existing:
            conn.close()
            return jsonify({'success': False, 'error': 'Username or email already exists'})
    
    # Update user
    updates = []
    values = []
    
    if username:
        updates.append('username = ?')
        values.append(username)
    
    if email:
        updates.append('email = ?')
        values.append(email)
    
    if password:
        updates.append('password = ?')
        values.append(generate_password_hash(password))
    
    if is_admin is not None:
        updates.append('is_admin = ?')
        values.append(1 if is_admin else 0)
    
    if updates:
        values.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)
        conn.commit()
    
    conn.close()
    return jsonify({'success': True})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    # Prevent admin from deleting themselves
    if user_id == session.get('user_id'):
        return jsonify({'success': False, 'error': 'Cannot delete your own account'})
    
    conn = get_db_connection()
    
    # Check if user exists
    user = conn.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'})
    
    # Delete user
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True})

# Add these routes for backup functionality
@app.route('/admin/backup')
@admin_required
def admin_backup():
    # Get list of backups
    backup_dir = os.path.join(app.root_path, 'backups')
    os.makedirs(backup_dir, exist_ok=True)
    
    backups = []
    for filename in os.listdir(backup_dir):
        if filename.endswith('.zip'):
            file_path = os.path.join(backup_dir, filename)
            file_stats = os.stat(file_path)
            size_in_mb = file_stats.st_size / (1024 * 1024)
            
            backups.append({
                'filename': filename,
                'created': datetime.datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'size': f"{size_in_mb:.2f} MB"
            })
    
    # Sort backups by creation date (newest first)
    backups.sort(key=lambda x: x['created'], reverse=True)
    
    return render_template('admin/backup.html', backups=backups)

@app.route('/admin/backup/create', methods=['POST'])
@admin_required
def admin_create_backup():
    try:
        # Create backup directory if it doesn't exist
        backup_dir = os.path.join(app.root_path, 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        # Generate backup filename with timestamp
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.zip"
        backup_path = os.path.join(backup_dir, backup_filename)
        
        # Create zip file
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add database file
            zipf.write(DATABASE, arcname=os.path.basename(DATABASE))
            
            # Add uploaded documents
            for root, _, files in os.walk(app.config['UPLOAD_FOLDER']):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, os.path.dirname(app.config['UPLOAD_FOLDER']))
                    zipf.write(file_path, arcname=arcname)
        
        flash('Backup created successfully!', 'success')
        return redirect(url_for('admin_backup'))
    
    except Exception as e:
        flash(f'Error creating backup: {str(e)}', 'error')
        return redirect(url_for('admin_backup'))

@app.route('/admin/backup/download/<filename>')
@admin_required
def admin_download_backup(filename):
    backup_dir = os.path.join(app.root_path, 'backups')
    file_path = os.path.join(backup_dir, filename)
    
    if not os.path.exists(file_path):
        flash('Backup file not found', 'error')
        return redirect(url_for('admin_backup'))
    
    return send_file(
        file_path,
        as_attachment=True,
        download_name=filename
    )

@app.route('/admin/backup/import', methods=['POST'])
@admin_required
def admin_import_backup():
    if 'backup_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('admin_backup'))
    
    file = request.files['backup_file']
    
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('admin_backup'))
    
    if not file.filename.endswith('.zip'):
        flash('Only .zip files are allowed', 'error')
        return redirect(url_for('admin_backup'))
    
    try:
        # Create temporary directory for extraction
        temp_dir = os.path.join(app.root_path, 'temp_backup')
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save and extract the zip file
        zip_path = os.path.join(temp_dir, 'backup.zip')
        file.save(zip_path)
        
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(temp_dir)
        
        # Close database connection
        conn = get_db_connection()
        conn.close()
        
        # Replace database file
        db_file = os.path.join(temp_dir, os.path.basename(DATABASE))
        if os.path.exists(db_file):
            shutil.copy2(db_file, DATABASE)
        else:
            raise Exception("Database file not found in backup")
        
        # Replace uploaded documents
        documents_dir = os.path.join(temp_dir, 'documents')
        if os.path.exists(documents_dir):
            # Clear existing documents directory
            shutil.rmtree(app.config['UPLOAD_FOLDER'])
            # Copy documents from backup
            shutil.copytree(documents_dir, app.config['UPLOAD_FOLDER'])
        else:
            raise Exception("Documents directory not found in backup")
        
        # Clean up
        shutil.rmtree(temp_dir)
        
        flash('Backup imported successfully!', 'success')
        return redirect(url_for('admin_backup'))
    
    except Exception as e:
        flash(f'Error importing backup: {str(e)}', 'error')
        return redirect(url_for('admin_backup'))

@app.route('/admin/backup/delete/<filename>', methods=['DELETE'])
@admin_required
def admin_delete_backup(filename):
    try:
        backup_dir = os.path.join(app.root_path, 'backups')
        file_path = os.path.join(backup_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'success': False, 'error': 'Backup file not found'})
        
        os.remove(file_path)
        return jsonify({'success': True})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Helper function for spell checking
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

@app.route('/test')
def test():
    return render_template('test.html')


# Initialize the spell checker
spell = SpellChecker()

@app.route('/')
def home():  # Renamed function to 'home'
    return render_template('spell.html')  # Updated template to 'spell.html'

@app.route('/check_spelling', endpoint='check_spelling_route')  # Set a custom endpoint
def check_spelling():
    word = request.args.get('word', '').strip()

    if word:
        # Check if the word is correct or not
        is_correct = spell.unknown([word]) == set()

        # Get suggestions if the word is incorrect
        suggestions = spell.candidates(word) if not is_correct else []

        return jsonify({
            'isCorrect': is_correct,
            'suggestions': list(suggestions)
        })
    return jsonify({'isCorrect': False, 'suggestions': []})



if __name__ == '__main__':
   
    # Initialize database if it doesn't exist
    if not os.path.exists(DATABASE):
        init_db()
    
    app.run(debug=True)
