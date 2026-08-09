# Soteria-AI Backend

## Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate    # macOS/Linux
# venv\Scripts\activate     # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000`
API docs at `http://localhost:8000/docs`
