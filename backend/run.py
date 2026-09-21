"""
Development server startup script for PROJECT_NAME backend.
"""
import uvicorn

if __name__ == "__main__":
    print("==================================================================")
    print("PROJECT_NAME: AI-Powered Email Threat Detection & Forensic Platform")
    print("SIH 2026 Problem Statement SIH26106 | Modular Monolith Backend")
    print("Swagger Documentation: http://localhost:8000/docs")
    print("API Endpoint: http://localhost:8000/api/v1/health")
    print("==================================================================")
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
