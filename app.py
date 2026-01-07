import streamlit as st
import hashlib
import os
import pandas as pd
import time

# --- Functions ---
def calculate_sha256(file_obj):
    """Calculate SHA-256 for an uploaded file object."""
    sha256_hash = hashlib.sha256()
    # Read the file in chunks
    for byte_block in iter(lambda: file_obj.read(4096), b""):
        sha256_hash.update(byte_block)
    file_obj.seek(0) # Reset file pointer
    return sha256_hash.hexdigest()

# --- UI Setup ---
st.set_page_config(page_title="Cyber Guard FIM", page_icon="🛡️")
st.title("🛡️ File Integrity Monitor (FIM)")
st.markdown("""
This tool uses **SHA-256 Hashing** to ensure your files haven't been tampered with. 
Upload a file to establish a **Baseline**, then re-upload later to **Verify Integrity**.
""")

# --- Sidebar / State ---
if 'baseline_hash' not in st.session_state:
    st.session_state.baseline_hash = None

# --- Main App Logic ---
uploaded_file = st.file_uploader("Choose a file to monitor", type=['txt', 'pdf', 'png', 'jpg', 'docx'])

if uploaded_file is not None:
    current_hash = calculate_sha256(uploaded_file)
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("Set as Baseline"):
            st.session_state.baseline_hash = current_hash
            st.session_state.filename = uploaded_file.name
            st.success(f"✅ Baseline established for {uploaded_file.name}")
            st.code(current_hash, language="text")

    with col2:
        if st.button("Verify Integrity"):
            if st.session_state.baseline_hash is None:
                st.error("❌ No baseline found! Set a baseline first.")
            else:
                st.info(f"Comparing against baseline for: {st.session_state.filename}")
                if current_hash == st.session_state.baseline_hash:
                    st.success("💎 MATCH: File is authentic. No changes detected.")
                else:
                    st.error("⚠️ ALERT: Hashes do not match! The file has been tampered with.")
                    st.write(f"**Current Hash:** `{current_hash}`")
                    st.write(f"**Baseline Hash:** `{st.session_state.baseline_hash}`")

# --- Visual Aid for Portfolio ---
st.divider()
st.subheader("How it works: The CIA Triad")
st.write("This tool focuses on **Integrity** by verifying that data remains unchanged.")
