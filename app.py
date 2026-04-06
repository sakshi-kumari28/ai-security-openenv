# Replace app.py content with just:
echo "from environment import app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7860)" > app.py

git add app.py
git commit -m "fix: app.py now runs Flask server"
git push
