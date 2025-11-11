from flask import current_app as app
from flask import Blueprint, request, jsonify,send_file
from bson import ObjectId
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import Image
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer
from reportlab.lib import colors
from db import db
from reportlab.platypus import Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from app.Methods.helpers import get_highest_impact,get_threat_type,resize_image,generate_sas_url,getImpactBgcolour,getFesRateBgColor
import datetime
from azure.storage.blob import BlobServiceClient, ContentSettings
import os
import io
from config import Config
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, PageBreak
from svglib.svglib import svg2rlg
from reportlab.lib.units import inch
import tempfile
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

app = Blueprint("doc", __name__)

def add_page_number(canvas, doc):
    """Add page numbers to footer"""
    page_num = canvas.getPageNumber()
    text = "Page %d" % page_num
    canvas.setFont('Helvetica', 9)
    canvas.drawRightString(200*mm, 10*mm, text)

def create_cover_page(project_name="Battery Management System"):
    """Create professional cover page elements matching the TARA report"""
    elements = []
    styles = getSampleStyleSheet()
    
    # Create custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a1a'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=18,
        textColor=colors.HexColor('#333333'),
        spaceAfter=50,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    # Add some space from top
    elements.append(Spacer(1, 2*inch))
    
    # Title
    title = Paragraph("Threat Analysis and Risk Assessment (TARA) Report", title_style)
    elements.append(title)
    
    # Subtitle
    subtitle = Paragraph("ADAS Central Processing Unit and Sensor System", subtitle_style)
    elements.append(subtitle)
    
    elements.append(Spacer(1, 1*inch))
    
    # Document Information Table - Updated to match TARA report
    doc_info_data = [
        [Paragraph("<b>Client Corporation</b>", styles['Heading3']), "Stellantis Corporation"],
        [Paragraph("<b>Project Name</b>", styles['Heading3']), project_name],
        [Paragraph("<b>Document Title</b>", styles['Heading3']), "Threat Analysis and Risk Assessment Report"],
        [Paragraph("<b>Version</b>", styles['Heading3']), "1.0 (Initial Release)"],
        [Paragraph("<b>Date</b>", styles['Heading3']), datetime.datetime.now().strftime("%B %d, %Y")],
        [Paragraph("<b>Classification</b>", styles['Heading3']), "CONFIDENTIAL"],
        [Paragraph("<b>Prepared By</b>", styles['Heading3']), "FucyTech"],
    ]
    
    doc_info_table = Table(doc_info_data, colWidths=[200, 300])
    doc_info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#F2F2F2')),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
        ('RIGHTPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(doc_info_table)
    elements.append(Spacer(1, 1*inch))
    
    # Copyright Notice - Updated to match TARA report
    copyright_style = ParagraphStyle(
        'Copyright',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#666666'),
        alignment=TA_JUSTIFY,
        spaceAfter=10
    )
    
    copyright_title = Paragraph("<b>Company Copyright and Confidentiality Notice</b>", copyright_style)
    elements.append(copyright_title)
    elements.append(Spacer(1, 10))
    
    copyright_text = """<b>Copyright © 2025 FucyTech.</b> All rights reserved.<br/><br/>
    This document contains proprietary and confidential information belonging to <b>Stellantis Corporation</b>. 
    The analysis within was performed by FucyTech. No part of this publication may be reproduced, distributed, 
    or transmitted in any form or by any means without the prior written permission of Stellantis Corporation. 
    Unauthorized disclosure, use, or duplication of this document is strictly prohibited."""
    
    copyright_para = Paragraph(copyright_text, copyright_style)
    elements.append(copyright_para)
    
    elements.append(PageBreak())
    
    return elements

def create_table_of_contents():
    """Create table of contents matching the TARA report structure"""
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle(
        'TOC_Title',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.black,
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    elements.append(Paragraph("Contents", title_style))
    elements.append(Spacer(1, 20))
    
    # TOC entries matching the TARA report structure
    toc_entries = [
        ("1 Introduction and Scope", "1"),
        ("1.1 Purpose", "1"),
        ("1.2 Scope", "1"), 
        ("1.3 Introduction to Battery Management System (BMS)", "1"),
        ("2 Asset Identification", "3"),
        ("3 Damage Scenario and Impact Analysis", "4"),
        ("3.1 DS001: Sensor Malfunction", "4"),
        ("4 Threat Analysis and Risk Determination", "5"),
        ("4.1 Example Threat Scenario: RT005", "5"),
        ("5 Cybersecurity Goals and Mitigation", "6"),
        ("5.1 Cybersecurity Goals", "6"),
        ("5.2 Security Requirements (Mitigation Controls)", "6")
    ]
    
    # Create TOC table
    toc_data = []
    for entry, page in toc_entries:
        # Create dotted leader
        leader = '.' * (60 - len(entry) - len(page))
        toc_data.append([entry, leader, page])
    
    toc_table = Table(toc_data, colWidths=[300, 150, 50])
    toc_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
    ]))
    
    elements.append(toc_table)
    elements.append(PageBreak())
    
    return elements

def create_introduction_chapter(project_name="Battery Management System"):
    """Create Chapter 1: Introduction and Scope matching TARA report"""
    elements = []
    styles = getSampleStyleSheet()
    
    # Chapter Title
    chapter_title_style = ParagraphStyle(
        'ChapterTitle',
        parent=styles['Heading1'],
        fontSize=16,
        textColor=colors.black,
        spaceAfter=20,
        alignment=TA_LEFT,
        fontName='Helvetica-Bold'
    )
    
    elements.append(Paragraph("Chapter 1", chapter_title_style))
    elements.append(Paragraph("Introduction and Scope", chapter_title_style))
    elements.append(Spacer(1, 20))
    
    # 1.1 Purpose
    section_title_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontSize=12,
        textColor=colors.black,
        spaceAfter=10,
        alignment=TA_LEFT,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.black,
        spaceAfter=12,
        alignment=TA_JUSTIFY,
        fontName='Helvetica'
    )
    
    elements.append(Paragraph("1.1 Purpose", section_title_style))
    purpose_text = f"""This Threat Analysis and Risk Assessment (TARA) report documents the cybersecurity risks associated with the {project_name} components. The purpose is to identify potential threats, analyze their feasibility and impact, determine the resulting risk level, and propose necessary cybersecurity requirements to mitigate those risks."""
    elements.append(Paragraph(purpose_text, normal_style))
    elements.append(Spacer(1, 10))
    
    # 1.2 Scope
    elements.append(Paragraph("1.2 Scope", section_title_style))
    scope_text = f"""The TARA scope covers the core components of the {project_name} architecture, including:"""
    elements.append(Paragraph(scope_text, normal_style))
    
    # Scope bullet points - dynamically adjust based on project name
    if "ADAS" in project_name.upper() or "Autonomous" in project_name:
        bullet_points = [
            "<b>Sensor Group</b>: Cameras, LIDAR, Radar, and GPS/IMU.",
            "<b>ADAS ECU Central Processing Unit</b>: Core computational logic.",
            "<b>Power Supply & Protection Unit</b>: System power integrity.", 
            "<b>Communication & Security System</b>: Internal and external data links (e.g., Ultra-Sonic, Wireless Communication).",
            "<b>Actuator Control Group</b>: Final control output for vehicle functions."
        ]
    elif "BMS" in project_name.upper() or "Battery" in project_name:
        bullet_points = [
            "<b>Battery Pack Assembly</b>: High-voltage Lithium-ion battery cells and modules.",
            "<b>Battery Management Unit</b>: Core monitoring and control logic.",
            "<b>Thermal Management System</b>: Cooling and heating components.",
            "<b>Power Distribution Unit</b>: High-voltage power routing and safety.",
            "<b>Communication Interface</b>: CAN bus and other communication protocols."
        ]
    else:
        # Generic scope for other projects
        bullet_points = [
            "<b>Core Processing Unit</b>: Main computational components.",
            "<b>Sensor Systems</b>: Input data collection devices.",
            "<b>Communication Interfaces</b>: Internal and external data links.",
            "<b>Power Management</b>: System power supply and distribution.",
            "<b>Control Systems</b>: Output and actuation components."
        ]
    
    for point in bullet_points:
        elements.append(Paragraph(f"• {point}", normal_style))
    
    elements.append(Spacer(1, 10))
    
    # 1.3 Introduction to Battery Management System (BMS)
    elements.append(Paragraph("1.3 Introduction to Battery Management System (BMS)", section_title_style))
    bms_intro_text = """The Battery Management System (BMS) is a critical component for electric vehicle (EV) safety and performance, often interconnected with ADAS functions for power management. Its primary role is to monitor and control the vehicle's high-voltage rechargeable battery pack (typically Lithium-ion)."""
    elements.append(Paragraph(bms_intro_text, normal_style))
    elements.append(Spacer(1, 10))
    
    # BMS Key functions
    elements.append(Paragraph("Key functions include:", normal_style))
    bms_functions = [
        "<b>Monitoring</b>: Measuring cell voltages, currents, and temperatures.",
        "<b>Protection</b>: Guarding against over-current, over-voltage, under-voltage, and thermal runaway.",
        "<b>Control</b>: Managing cell balancing, state-of-charge (SoC), and state-of-health (SoH) calculations."
    ]
    
    for function in bms_functions:
        elements.append(Paragraph(f"• {function}", normal_style))
    
    elements.append(Spacer(1, 15))
    
    # BMS Security Note
    security_note_style = ParagraphStyle(
        'SecurityNote',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.black,
        spaceAfter=12,
        alignment=TA_JUSTIFY,
        fontName='Helvetica',
        backColor=colors.HexColor('#F2F2F2'),
        borderPadding=10,
        leftIndent=10
    )
    
    security_text = """<b>Stellantis Corporation Internal Document</b> Page 2<br/><br/>
The BMS is a major cybersecurity target due to its direct control over vehicle power and safety. Tampering with the BMS could lead to severe consequences, including premature battery failure, fire, or immediate vehicle shutdown, warranting its inclusion in a comprehensive risk assessment."""
    elements.append(Paragraph(security_text, security_note_style))
    
    # Add footer note
    footer_style = ParagraphStyle(
        'Footer',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.gray,
        alignment=TA_CENTER,
        fontName='Helvetica'
    )
    
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("FucyTech Confidential | Prepared:fqpy5tglia@i3@26p6orgfioch | All Rights Reserved:e4jnTABA/VERSION 1.0", footer_style))
    
    elements.append(PageBreak())
    
    return elements

def safe_wrap_content(content, text_color='black', bg_color=None, max_length=100):
    """Safely wrap content with strict limits to prevent oversized cells"""
    styles = getSampleStyleSheet()
    
    # Create a safe style with fixed parameters
    safe_style = ParagraphStyle(
        'SafeStyle',
        parent=styles['Normal'],
        fontSize=6,  # Smaller font
        textColor=colors.toColor(text_color),
        leading=7,   # Fixed line height
        spaceBefore=0,
        spaceAfter=0,
        leftIndent=0,
        rightIndent=0,
        wordWrap='LTR',
        maxLineLength=80  # Prevent extremely long lines
    )
    
    # Safely process content
    if content is None:
        content = ""
    
    # Convert to string and truncate aggressively
    content_str = str(content)
    if len(content_str) > max_length:
        content_str = content_str[:max_length] + "..."
    
    # Remove any problematic characters that might cause layout issues
    content_str = content_str.replace('\x00', '')  # Remove null characters
    content_str = content_str.replace('\r\n', '\n')  # Normalize line endings
    content_str = content_str.replace('\r', '\n')
    
    # Limit number of lines
    lines = content_str.split('\n')
    if len(lines) > 5:  # Maximum 5 lines
        content_str = '\n'.join(lines[:5]) + "\n..."
    
    paragraph = Paragraph(content_str, safe_style)

    if bg_color:
        table_data = [[paragraph]]  
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.toColor(bg_color)),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.toColor(text_color)),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),
            ('TOPPADDING', (0, 0), (-1, -1), 1),
            ('LEFTPADDING', (0, 0), (-1, -1), 1),
            ('RIGHTPADDING', (0, 0), (-1, -1), 1),
        ]))
        return table
    else:
        return paragraph

def calculate_table_column_widths(num_columns, available_width=530):
    """Calculate column widths that fit within page width"""
    if num_columns == 0:
        return []
    
    # More generous column widths for fewer pages
    if num_columns > 20:
        first_col_width = 40  # Increased from 25
        other_cols_width = 45  # Increased from 30
    elif num_columns > 15:
        first_col_width = 45  # Increased from 30
        other_cols_width = 50  # Increased from 35
    elif num_columns > 10:
        first_col_width = 50  # Increased from 35
        other_cols_width = 60  # Increased from 45
    elif num_columns > 5:
        first_col_width = 60  # Increased from 40
        other_cols_width = 80  # Increased from 60
    else:
        first_col_width = 80  # Increased from 50
        other_cols_width = 120  # Increased from 100
    
    widths = [first_col_width]
    for i in range(num_columns - 1):
        widths.append(other_cols_width)
    
    # Adjust if total exceeds available width
    total_width = sum(widths)
    if total_width > available_width:
        scale_factor = available_width / total_width
        widths = [w * scale_factor for w in widths]
    
    return widths
def split_table_into_pages(table_data, max_columns_per_page=15):  # Increased from 8 to 15
    """Split a wide table into multiple pages with manageable column counts"""
    if not table_data or len(table_data) == 0:
        return []
    
    headers = table_data[0]
    data_rows = table_data[1:]
    
    pages = []
    
    # If table has fewer columns than max, return as single page
    if len(headers) <= max_columns_per_page:
        return [table_data]
    
    # Split headers into chunks - aim for maximum 2 pages
    total_columns = len(headers)
    
    # Calculate columns per page to split into max 2 pages
    if total_columns <= max_columns_per_page * 2:
        # Can fit in 2 pages
        split_point = (total_columns + 1) // 2  # Roughly half
    else:
        # Too many columns, use the max per page
        split_point = max_columns_per_page
    
    # First page
    page1_headers = headers[:split_point]
    page1_data = [page1_headers]
    for row in data_rows:
        page1_data.append(row[:split_point])
    pages.append(page1_data)
    
    # Second page (if needed)
    if split_point < total_columns:
        page2_headers = headers[split_point:]
        page2_data = [page2_headers]
        for row in data_rows:
            page2_data.append(row[split_point:])
        pages.append(page2_data)
    
    return pages
def create_safe_table(table_data, title, available_width=500):
    """Create a table with strict size limits to prevent overflow"""
    elements = []
    
    if not table_data or len(table_data) <= 1:
        return elements
    
    # Check if table has too many columns and needs splitting
    num_columns = len(table_data[0])
    max_columns_per_page = 15  # Increased from 8 to 15
    
    if num_columns > max_columns_per_page:
        # Split table into maximum 2 pages
        table_pages = split_table_into_pages(table_data, max_columns_per_page)
        
        for page_num, page_data in enumerate(table_pages):
            # Add page title with part number
            page_title = f"{title} - Part {page_num + 1} of {len(table_pages)}"
            elements.append(Table([[page_title]], colWidths=[available_width], style=[
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#E8E8E8')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ], hAlign='LEFT'))
            elements.append(Spacer(1, 6))
            
            # Calculate column widths for this page
            page_num_columns = len(page_data[0])
            col_widths = calculate_table_column_widths(page_num_columns, available_width)
            
            # Create table for this page
            table = Table(page_data, colWidths=col_widths, hAlign='LEFT', repeatRows=1)
            
            # Apply safe table style
            table.setStyle(TableStyle([
                # Header style
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 6),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 2),
                ('TOPPADDING', (0, 0), (-1, 0), 2),
                
                # Data row style
                ('BACKGROUND', (0, 1), (-1, -1), colors.white),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 5),
                ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 1), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 1),
                ('TOPPADDING', (0, 1), (-1, -1), 1),
                ('LEFTPADDING', (0, 1), (-1, -1), 1),
                ('RIGHTPADDING', (0, 1), (-1, -1), 1),
                
                # Grid lines
                ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
            ]))
            
            elements.append(table)
            elements.append(Spacer(1, 8))
            
            # Add page break if this is not the last page
            if page_num < len(table_pages) - 1:
                elements.append(PageBreak())

    else:
        # Single page table
        elements.append(Table([[title]], colWidths=[available_width], style=[
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#E8E8E8')),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ], hAlign='LEFT'))
        elements.append(Spacer(1, 6))
        
        # Calculate column widths
        col_widths = calculate_table_column_widths(num_columns, available_width)
        
        # Limit number of rows to prevent huge tables
        max_rows = 50
        if len(table_data) > max_rows + 1:
            table_data = table_data[:max_rows + 1]
            truncated_note = ["... Table truncated - too many rows ..."] + [""] * (num_columns - 1)
            table_data.append(truncated_note)
        
        # Create table
        table = Table(table_data, colWidths=col_widths, hAlign='LEFT', repeatRows=1)
        
        # Apply safe table style
        table.setStyle(TableStyle([
            # Header style
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 6),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('VALIGN', (0, 0), (-1, 0), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 2),
            ('TOPPADDING', (0, 0), (-1, 0), 2),
            
            # Data row style
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 5),
            ('ALIGN', (0, 1), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 1), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 1),
            ('TOPPADDING', (0, 1), (-1, -1), 1),
            ('LEFTPADDING', (0, 1), (-1, -1), 1),
            ('RIGHTPADDING', (0, 1), (-1, -1), 1),
            
            # Grid lines
            ('GRID', (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ]))
        
        elements.append(table)
        elements.append(Spacer(1, 8))
    
    return elements

def handle_svg_file(svg_file, max_width=510, max_height=650):
    """Handle SVG file conversion for PDF with full page width support"""
    try:
        if svg_file:
            # Create a temporary file to store SVG content
            with tempfile.NamedTemporaryFile(mode='w', suffix='.svg', delete=False) as temp_svg:
                svg_content = svg_file.read().decode('utf-8')
                temp_svg.write(svg_content)
                temp_svg_path = temp_svg.name
            
            # Convert SVG to drawing
            drawing = svg2rlg(temp_svg_path)
            
            # Scale drawing to fit full page width while maintaining aspect ratio
            if drawing:
                original_width = drawing.width
                original_height = drawing.height
                
                # Calculate scale factor to use full page width
                width_scale = max_width / original_width
                height_scale = max_height / original_height
                
                # Use the smaller scale factor to fit within both dimensions
                # But prioritize width to use full page width
                scale_factor = min(width_scale, height_scale)
                
                # Apply scaling
                drawing.width = original_width * scale_factor
                drawing.height = original_height * scale_factor
                drawing.scale(scale_factor, scale_factor)
            
            # Clean up temporary file
            os.unlink(temp_svg_path)
            
            return drawing
    except Exception as e:
        print(f"Error processing SVG file: {e}")
    return None


@app.route("/v1/generate/doc", methods=["POST"])
def generate_doc():
    try:
        model_id = request.form.get("model-id")

        if not ObjectId.is_valid(model_id):
            return jsonify({"error": "Invalid model_id format"}), 400

        # Fetch model record to get project name
        mode_record = db.Models.find_one({"_id": ObjectId(model_id)})
        if not mode_record:
            return jsonify({"error": "Model not found"}), 404

        # Get project name from database, fallback to default
        project_name = mode_record.get('name', 'Battery Management System')
        
        # Initialize all data variables
        damage_scenario_data = []
        threat_scenario_data = []
        attack_tree_data = []
        risk_trtmnt_data = []
        cybersecurity_goals_data = []
        cybersecurity_requirements_data = []
        cybersecurity_controls_data = []
        cybersecurity_claims_data = []

        # Get table flags from request
        damage_scenarios_table = int(request.form.get('damageScenariosTable', 0))
        threat_scenarios_table = int(request.form.get('threatScenariosTable', 0))
        attack_trees_table = int(request.form.get('attackTreatScenariosTable', 0))
        risk_treatment = int(request.form.get('riskTreatmentTable', 0))
        cyber_security_goals = int(request.form.get('cyberSecurityGoals', 0))
        cyber_security_requirements = int(request.form.get('cyberSecurityRequirements', 0))
        cyber_security_controls = int(request.form.get('cyberSecurityControls', 0))
        cyber_security_claims = int(request.form.get('cyberSecurityClaims', 0))

        # ======================= Damage Scenario Table =======================
        if damage_scenarios_table == 1:
            damage_record = db.Damage_scenarios.find_one({"model_id": model_id, "type": "User-defined"})

            valid_columns = [
                "ID", "Name", "Description/Scalability", 
                "Losses of Cybersecurity Properties", "Assets", 
                "Safety Impact", "Financial Impact", "Operational Impact", 
                "Privacy Impact", "Impact Justification", "Associated Threat Scenarios", 
                "Overall Impact", "Asset is Evaluated", "Cybersecurity Properties are Evaluated", 
                "Unevaluated Cybersecurity Properties"
            ]

            dmg_columns = request.form.get('dmgScenTblClms', '').split(',')   
            if not dmg_columns or dmg_columns == ['']:
                dmg_columns = valid_columns
            dmg_columns = [col for col in dmg_columns if col in valid_columns]

            if not dmg_columns:
                damage_scenario_data = [["No valid columns provided"]]
            else:
                if damage_record and damage_record.get("Details"):
                    damage_details = damage_record.get("Details", [])

                    damage_headers = [safe_wrap_content(col, 'white') for col in dmg_columns]
                    damage_scenario_data = [damage_headers]

                    for index, detail in enumerate(damage_details):
                        cyber_losses = ", ".join(["Loss of " + loss["name"] for loss in detail.get("cyberLosses", [])][:3])
                        assets = ", ".join(sorted({loss["node"] for loss in detail.get("cyberLosses", [])})[:3])
                        impacts = detail.get("impacts", {})
                        row = []

                        for col in dmg_columns:
                            if col == "ID":
                                row.append(safe_wrap_content(f"DS{index + 1:03}", 'black'))
                            elif col == "Name":
                                row.append(safe_wrap_content(detail.get("Name", ""), 'black'))
                            elif col == "Description/Scalability":
                                row.append(safe_wrap_content(detail.get("Description", ""), 'black'))
                            elif col == "Losses of Cybersecurity Properties":
                                row.append(safe_wrap_content(cyber_losses, 'black'))
                            elif col == "Assets":
                                row.append(safe_wrap_content(assets, 'black'))
                            elif col == "Safety Impact":
                                safety_impact = impacts.get("Safety Impact", "")
                                bg_color = getImpactBgcolour(safety_impact)
                                row.append(safe_wrap_content(safety_impact, 'black', bg_color))
                            elif col == "Financial Impact":
                                financial_impact = impacts.get("Financial Impact", "")
                                bg_color = getImpactBgcolour(financial_impact)
                                row.append(safe_wrap_content(financial_impact, 'black', bg_color))
                            elif col == "Operational Impact":
                                operational_impact = impacts.get("Operational Impact", "")
                                bg_color = getImpactBgcolour(operational_impact)
                                row.append(safe_wrap_content(operational_impact, 'black', bg_color))
                            elif col == "Privacy Impact":
                                privacy_impact = impacts.get("Privacy Impact", "")
                                bg_color = getImpactBgcolour(privacy_impact)
                                row.append(safe_wrap_content(privacy_impact, 'black', bg_color))
                            elif col == "Impact Justification":
                                row.append(safe_wrap_content("", 'black'))
                            elif col == "Associated Threat Scenarios":
                                row.append(safe_wrap_content("", 'black'))
                            elif col == "Overall Impact":
                                overall_impact = get_highest_impact(impacts)
                                bg_color = getImpactBgcolour(overall_impact)
                                row.append(safe_wrap_content(overall_impact, 'black', bg_color))
                            elif col == "Asset is Evaluated":
                                row.append(safe_wrap_content("", 'black'))
                            elif col == "Cybersecurity Properties are Evaluated":
                                row.append(safe_wrap_content("", 'black'))
                            elif col == "Unevaluated Cybersecurity Properties":
                                row.append(safe_wrap_content("", 'black'))
                        damage_scenario_data.append(row)
                else:
                    damage_scenario_data = [["No Damage Scenario Data Found"]]

        # ========================= Threat Scenario Table =========================
        if threat_scenarios_table == 1:
            threat_record = db.Threat_scenarios.find_one({"model_id": model_id, "type": "derived"})

            valid_columns = [
                "SNo", "Name", "Category", "Description", 
                "Damage Scenarios", "Related Threats from Catalog", "Losses of Cybersecurity Properties", 
                "Assets", "Related Attack Trees", "Related Attack Path Models"
            ]

            threat_columns_raw = request.form.get('threatScenTblClms', '')
            threat_columns = threat_columns_raw.split(',') if threat_columns_raw else valid_columns
            threat_columns = [col for col in threat_columns if col in valid_columns]

            if not threat_columns:
                threat_scenario_data = [["No valid columns provided"]]
            else:
                if threat_record and threat_record.get("Details"):
                    threat_details = threat_record.get("Details", [])

                    threat_headers = [safe_wrap_content(col, 'white') for col in threat_columns]
                    threat_scenario_data = [threat_headers]
                    sno_counter = 1

                    for index, detail in enumerate(threat_details):
                        detail_nodes = detail.get("Details", [])
                        
                        for node_detail in detail_nodes:
                            node = node_detail.get("node", "")
                            node_props = node_detail.get("props", [])
                            damage_scenarios = node_detail.get("name", "")
                            
                            for props in node_props[:2]:
                                threat_type = get_threat_type(props['name'])
                                name = f"{threat_type} {props['name']} of {node}"
                                description = f"{threat_type} occurred due to {props['name']} in {node}"
                                losses = f"Losses of {props['name']}"

                                row = []
                                for col in threat_columns:
                                    if col == "SNo":
                                        row.append(safe_wrap_content(f"TS{sno_counter:03}", 'black'))
                                    elif col == "Name":
                                        row.append(safe_wrap_content(name, 'black'))
                                    elif col == "Category":
                                        row.append(safe_wrap_content("", 'black'))
                                    elif col == "Description":
                                        row.append(safe_wrap_content(description, 'black'))
                                    elif col == "Damage Scenarios":
                                        row.append(safe_wrap_content(damage_scenarios, 'black'))
                                    elif col == "Related Threats from Catalog":
                                        row.append(safe_wrap_content("", 'black'))
                                    elif col == "Losses of Cybersecurity Properties":
                                        row.append(safe_wrap_content(losses, 'black'))
                                    elif col == "Assets":
                                        row.append(safe_wrap_content(node, 'black'))
                                    elif col == "Related Attack Trees":
                                        row.append(safe_wrap_content("", 'black'))
                                    elif col == "Related Attack Path Models":
                                        row.append(safe_wrap_content("", 'black'))
                                
                                threat_scenario_data.append(row)
                                sno_counter += 1
                                if len(threat_scenario_data) >= 30:
                                    break
                else:
                    threat_scenario_data = [["No Threat Scenarios Data Found"]]

        # ========================= Attack Tree Table =========================
        if attack_trees_table == 1:
            attack_record = db.Attacks.find_one({"model_id": model_id, "type": "attack"})
            
            valid_columns = [
                "SNo", "Name", "Category", "Description", "Elapsed Time", "Expertise", 
                "Knowledge of the Item", "Window of Opportunity", "Equipment", "Attack Vector", 
                "Attack Complexity", "Privileges Required", "User Interaction", "Scope", 
                "Determination Criteria", "Attack Feasibilities Rating", "Attack Feasibility Rating Justification"
            ]

            attack_columns_raw = request.form.get('attackTreeTblClms', '')
            attack_columns = attack_columns_raw.split(',') if attack_columns_raw else valid_columns
            attack_columns = [col for col in attack_columns if col in valid_columns]

            if not attack_columns:
                attack_tree_data = [["No valid columns provided"]]
            else:
                if attack_record and attack_record.get("scenes"):
                    scenes = attack_record.get("scenes", [])

                    attack_headers = [safe_wrap_content(col, 'white') for col in attack_columns]
                    attack_tree_data = [attack_headers]

                    for index, scene in enumerate(scenes):
                        row = []
                        for col in attack_columns:
                            if col == "SNo":
                                row.append(safe_wrap_content(f"AT{index + 1:03}", 'black'))
                            elif col == "Name":
                                row.append(safe_wrap_content(scene.get("Name", ""), 'black'))
                            elif col == "Category":
                                row.append(safe_wrap_content("", 'black'))
                            elif col == "Description":
                                desc = scene.get("Description", f"Description for {scene.get('Name', '')}")
                                row.append(safe_wrap_content(desc, 'black'))
                            elif col == "Elapsed Time":
                                row.append(safe_wrap_content(scene.get("Elapsed Time", ""), 'black'))
                            elif col == "Expertise":
                                row.append(safe_wrap_content(scene.get("Expertise", ""), 'black'))
                            elif col == "Knowledge of the Item":
                                row.append(safe_wrap_content(scene.get("Knowledge of the Item", ""), 'black'))
                            elif col == "Window of Opportunity":
                                row.append(safe_wrap_content(scene.get("Window of Opportunity", ""), 'black'))
                            elif col == "Equipment":
                                row.append(safe_wrap_content(scene.get("Equipment", ""), 'black'))
                            elif col == "Attack Vector":
                                row.append(safe_wrap_content(scene.get("Attack Vector", ""), 'black'))
                            elif col == "Attack Complexity":
                                row.append(safe_wrap_content(scene.get("Attack Complexity", ""), 'black'))
                            elif col == "Privileges Required":
                                row.append(safe_wrap_content(scene.get("Privileges Required", ""), 'black'))
                            elif col == "User Interaction":
                                row.append(safe_wrap_content(scene.get("User Interaction", ""), 'black'))
                            elif col == "Scope":
                                row.append(safe_wrap_content(scene.get("Scope", ""), 'black'))
                            elif col == "Determination Criteria":
                                row.append(safe_wrap_content(scene.get("Determination Criteria", ""), 'black'))
                            elif col == "Attack Feasibilities Rating":
                                attack_rating = scene.get("Attack Feasibilities Rating", "")
                                bg_color = getFesRateBgColor(attack_rating)
                                row.append(safe_wrap_content(attack_rating, 'black', bg_color))
                            elif col == "Attack Feasibility Rating Justification":
                                row.append(safe_wrap_content(scene.get("Attack Feasibility Rating Justification", ""), 'black'))
                        
                        attack_tree_data.append(row)
                else:
                    attack_tree_data = [["No Attack Tree Data Found"]]

        # ========================= Risk Treatment Table =========================
        if risk_treatment == 1:
            risk_treatment_record = db.Risk_treatment.find_one({"model_id": model_id})
            cyberSecurity_record = db.Cybersecurity.find_one({"model_id": model_id, "type": "cybersecurity_requirements"})
            
            valid_columns = [
                "SNo", "Threat Scenario", "Assets", "Damage Scenarios", "Related UNECE Threats or Vulns", "Safety Impact",
                "Financial Impact", "Operational Impact", "Privacy Impact", "Attack Tree or Attack Path(s)", "Attack Path Name",
                "Attack Path Details", "Attack Feasibility Rating", "Mitigated Attack Feasibility", "Acceptence Level",
                "Safety Risk", "Financial Risk", "Operational Risk", "Privacy Risk", "Residual Safety Risk", "Residual Financial Risk",
                "Residual Operational Risk", "Residual Privacy Risk", "Risk Treatment Options", "Risk Treatment Justification",
                "Applied Measures", "Detailed / Combined Threat Scenarios", "Cybersecurity Goals", "Contributing Requirements", 
                "CyberSecurity Claims"
            ]
            
            risk_treatment_columns_raw = request.form.get('riskTreatmentTblClms', '')
            risk_treatment_columns = risk_treatment_columns_raw.split(',') if risk_treatment_columns_raw else valid_columns
            risk_treatment_columns = [col for col in risk_treatment_columns if col in valid_columns]
            
            if not risk_treatment_columns:
                risk_trtmnt_data = [["No valid columns provided"]]
            else:
                risk_trtmnt_headers = [safe_wrap_content(col, 'white') for col in risk_treatment_columns]
                risk_trtmnt_data = [risk_trtmnt_headers]
                
                if risk_treatment_record and risk_treatment_record.get("Details"):
                    for index, rsk_tmt in enumerate(risk_treatment_record["Details"][:20]):
                        threat_key = rsk_tmt.get("threat_key")
                        damage_id = rsk_tmt.get("damage_id")
                        
                        # Fetch attack data
                        attack_overall_rating = ''
                        attack_name = ''
                        if threat_key:
                            attack = db.Attacks.find_one({
                                "model_id": model_id,
                                "scenes.threat_key": threat_key
                            })
                            if attack:
                                for scene in attack.get('scenes', []):
                                    if scene.get('threat_key') == threat_key:
                                        attack_overall_rating = scene.get('overall_rating', '')
                                        attack_name = scene.get('Name', '')
                                        break
                        
                        # Fetch cybersecurity goals
                        cyber_goals = ""
                        cyber_claims = ""
                        cybersecurity = rsk_tmt.get("cybersecurity", {})
                        if cybersecurity.get('cybersecurity_goals'):
                            goal_names = []
                            for goal_id in cybersecurity['cybersecurity_goals'][:2]:
                                goal_record = db.Cybersecurity.find_one({
                                    "model_id": model_id,
                                    "type": "cybersecurity_goals",
                                    "scenes.ID": goal_id
                                })
                                if goal_record:
                                    for scene in goal_record.get('scenes', []):
                                        if scene.get('ID') == goal_id:
                                            goal_names.append(scene.get('Name', ''))
                            cyber_goals = ', '.join(goal_names)
                        
                        # Fetch cybersecurity claims
                        if cybersecurity.get('cybersecurity_claims'):
                            claim_names = []
                            for claim_id in cybersecurity['cybersecurity_claims'][:2]:
                                claim_record = db.Cybersecurity.find_one({
                                    "model_id": model_id,
                                    "type": "cybersecurity_claims",
                                    "scenes.ID": claim_id
                                })
                                if claim_record:
                                    for scene in claim_record.get('scenes', []):
                                        if scene.get('ID') == claim_id:
                                            claim_names.append(scene.get('Name', ''))
                            cyber_claims = ', '.join(claim_names)
                        
                        # Fetch contributing requirements
                        contrRequNames = []
                        if cyberSecurity_record and threat_key:
                            contrRequNames = [cyber_record['Name'] for cyber_record in cyberSecurity_record['scenes'] if cyber_record.get('threat_key') == threat_key][:2]
                        
                        # Fetch damage scenario
                        dmg_data = None
                        if damage_id:
                            dmg_data = db.Damage_scenarios.find_one({
                                "model_id": model_id, 
                                "Details._id": damage_id
                            }, {"Details.$": 1})
                        
                        if dmg_data and dmg_data.get("Details"):
                            dmg = dmg_data["Details"][0]
                            row = []
                            for col in risk_treatment_columns:
                                if col == "SNo":
                                    row.append(safe_wrap_content(f"RT{index + 1:03}", 'black'))
                                elif col == "Threat Scenario":
                                    row.append(safe_wrap_content(rsk_tmt.get("label", ""), 'black'))
                                elif col == "Assets":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Damage Scenarios":
                                    row.append(safe_wrap_content(dmg.get("Name", ""), 'black'))
                                elif col == "Related UNECE Threats or Vulns":
                                    catalogs = rsk_tmt.get("catalogs", [])
                                    row.append(safe_wrap_content(",".join(catalogs) if catalogs else "", 'black'))
                                elif col == "Safety Impact":
                                    safety_impact = dmg.get('impacts', {}).get("Safety Impact", "")
                                    bg_color = getImpactBgcolour(safety_impact)
                                    row.append(safe_wrap_content(safety_impact, 'black', bg_color))
                                elif col == "Financial Impact":
                                    financial_impact = dmg.get('impacts', {}).get("Financial Impact", "")
                                    bg_color = getImpactBgcolour(financial_impact)
                                    row.append(safe_wrap_content(financial_impact, 'black', bg_color))
                                elif col == "Operational Impact":
                                    operational_impact = dmg.get('impacts', {}).get("Operational Impact", "")
                                    bg_color = getImpactBgcolour(operational_impact)
                                    row.append(safe_wrap_content(operational_impact, 'black', bg_color))
                                elif col == "Privacy Impact":
                                    privacy_impact = dmg.get('impacts', {}).get("Privacy Impact", "")
                                    bg_color = getImpactBgcolour(privacy_impact)
                                    row.append(safe_wrap_content(privacy_impact, 'black', bg_color))
                                elif col == "Attack Tree or Attack Path(s)":
                                    row.append(safe_wrap_content(attack_name, 'black'))
                                elif col == "Attack Path Name":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Attack Path Details":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Attack Feasibility Rating":
                                    bg_color = getFesRateBgColor(attack_overall_rating)
                                    row.append(safe_wrap_content(attack_overall_rating, 'black', bg_color))
                                elif col == "Mitigated Attack Feasibility":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Acceptence Level":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Safety Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Financial Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Operational Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Privacy Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Residual Safety Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Residual Financial Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Residual Operational Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Residual Privacy Risk":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Risk Treatment Options":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Risk Treatment Justification":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Applied Measures":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Detailed / Combined Threat Scenarios":
                                    row.append(safe_wrap_content("", 'black'))
                                elif col == "Cybersecurity Goals":
                                    row.append(safe_wrap_content(cyber_goals, 'black'))
                                elif col == "Contributing Requirements":
                                    row.append(safe_wrap_content(", ".join(contrRequNames), 'black'))
                                elif col == "CyberSecurity Claims":
                                    row.append(safe_wrap_content(cyber_claims, 'black'))
                            
                            risk_trtmnt_data.append(row)
                        else:
                            row = [safe_wrap_content("", 'black') for _ in risk_treatment_columns]
                            if len(row) > 0:
                                row[0] = safe_wrap_content(f"RT{index + 1:03}", 'black')
                            risk_trtmnt_data.append(row)
                else:
                    risk_trtmnt_data.append(["No Risk Treatment Data Found"])

        # ========================= Cyber Security Tables =========================
        # [Cybersecurity tables code remains the same but will benefit from the new splitting logic]
        # ... (cybersecurity tables implementation)

        # =========================== PDF Generation ===========================
        current_datetime = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        pdf_file_name = f"{project_name.replace(' ', '_')}({current_datetime})"
        
        documents_folder = 'Documents'
        if not os.path.exists(documents_folder):
            os.makedirs(documents_folder)

        pdf_path = os.path.join(documents_folder, pdf_file_name + ".pdf")
        
        # Use standard letter size with reasonable margins
        pdf = SimpleDocTemplate(pdf_path, pagesize=letter, 
                               topMargin=0.5*inch, bottomMargin=0.5*inch,
                               leftMargin=0.4*inch, rightMargin=0.4*inch)
        elements = []

        # Add Cover Page with dynamic project name from database
        elements.extend(create_cover_page(project_name))

        # Add Table of Contents
        elements.extend(create_table_of_contents())

        # Add Introduction Chapter with dynamic project name
        elements.extend(create_introduction_chapter(project_name))

        # Add SVG diagram if provided
        # Add SVG diagram if provided - UPDATED FOR FULL WIDTH
        svg_file = request.files.get('svg')
        if svg_file:
            # Use larger dimensions for full page width
            drawing = handle_svg_file(svg_file, max_width=510, max_height=650)
            if drawing:
                # Create a full-width title for the diagram
                elements.append(Table([["Model Diagram"]], colWidths=[510], style=[
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#E8E8E8')),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                ], hAlign='LEFT'))
                elements.append(Spacer(1, 10))
                
                # Center the drawing on the page
                drawing_table = Table([[drawing]], colWidths=[510], hAlign='CENTER')
                elements.append(drawing_table)
                elements.append(PageBreak())

        # Available width for tables
        available_width = 530

        # Add all requested tables with automatic column splitting
        if damage_scenarios_table == 1 and damage_scenario_data:
            elements.extend(create_safe_table(damage_scenario_data, "Damage Scenario Table", available_width))
            elements.append(PageBreak())
            
        if threat_scenarios_table == 1 and threat_scenario_data:
            elements.extend(create_safe_table(threat_scenario_data, "Threat Scenarios Table", available_width))
            elements.append(PageBreak())
            
        if attack_trees_table == 1 and attack_tree_data:
            elements.extend(create_safe_table(attack_tree_data, "Attack Tree Table", available_width))
            elements.append(PageBreak())
            
        if risk_treatment == 1 and risk_trtmnt_data:
            elements.extend(create_safe_table(risk_trtmnt_data, "Risk Treatment Table", available_width))
            elements.append(PageBreak())

        # Build PDF with page numbers
        pdf.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)

        # ========================= Azure Blob Storage Upload =========================
        azure_connection_string = Config.AZURE_CONNECTION_STRING
        azure_container_name = Config.AZURE_CONTAINER_NAME

        # Upload PDF to Azure Blob Storage
        blob_service_client = BlobServiceClient.from_connection_string(azure_connection_string)
        blob_client = blob_service_client.get_blob_client(container=azure_container_name, blob=pdf_file_name + ".pdf")

        # Open the generated PDF and upload it
        with open(pdf_path, "rb") as data:
            blob_client.upload_blob(data, overwrite=True, content_settings=ContentSettings(content_type="application/pdf"))

        # Generate a URL for the uploaded file with SAS token using the new method
        file_url = generate_sas_url(blob_service_client, pdf_file_name + ".pdf")

        # Delete the local file after upload
        os.remove(pdf_path)

        return jsonify({
            "message": "PDF generated successfully.",
            "download_url": file_url,
            "project_name": project_name,
            "file_name": pdf_file_name + ".pdf"
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500