from reportlab.platypus import Image
import io
from PIL import Image as PILImage
from azure.storage.blob import (
    BlobServiceClient,
    BlobSasPermissions,
    generate_blob_sas,
    ContentSettings,
)
from reportlab.lib import colors
from config import Config
import datetime


def get_highest_impact(impacts):
    # impact_order = ["Severe", "Major", "Moderate", "Minor", "Negligible"]
    impact_order = ["Negligible", "Minor", "Moderate", "Major", "Severe"]

    # Extract values from the impacts dictionary and map them to their rank in the impact_order list
    impact_values = [
        (impacts.get("Safety Impact", ""), "Safety Impact"),
        (impacts.get("Financial Impact", ""), "Financial Impact"),
        (impacts.get("Operational Impact", ""), "Operational Impact"),
        (impacts.get("Privacy Impact", ""), "Privacy Impact"),
    ]

    # Determine the highest impact
    overall_impact = max(
        impact_values,
        key=lambda x: impact_order.index(x[0]) if x[0] in impact_order else -1,
    )[0]

    return overall_impact


def get_threat_type(value):
    mapping = {
        "Integrity": "Tampering",
        "Confidentiality": "Information Disclosure",
        "Availability": "Denial",
        "Authenticity": "Spoofing",
        "Authorization": "Elevation of Privilege",
        "Non-repudiation": "Rejection",
    }
    return mapping.get(value, "")


def get_highest_rating(ratings):
    rating_order = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4}
    highest_rating = None

    for rating in ratings:
        normalized_rating = rating.capitalize()  # Normalize to title case
        if normalized_rating in rating_order:
            if (
                highest_rating is None
                or rating_order[normalized_rating] > rating_order[highest_rating]
            ):
                highest_rating = normalized_rating

    return highest_rating


def resize_image(image_stream, max_width=500, max_height=400):
    # Open the image using Pillow
    img_pil = PILImage.open(image_stream)
    img_width, img_height = img_pil.size  # Get the image size (width, height)

    # Calculate aspect ratio
    aspect_ratio = img_width / img_height

    # Scale the image proportionally
    if img_width > max_width or img_height > max_height:
        if img_width > img_height:
            # Scale based on width
            img_width = max_width
            img_height = img_width / aspect_ratio
        else:
            # Scale based on height
            img_height = max_height
            img_width = img_height * aspect_ratio

    # Create a BytesIO stream to save the resized image
    img_pil = img_pil.resize((int(img_width), int(img_height)))
    img_byte_arr = io.BytesIO()
    img_pil.save(
        img_byte_arr, format="PNG"
    )  # Save image as PNG into the BytesIO stream
    img_byte_arr.seek(0)  # Reset stream position to the beginning

    # Now return the Image object for reportlab
    return Image(img_byte_arr)


def generate_sas_url(blob_service_client, blob_name):
    try:
        # Generate SAS token
        sas_token = generate_blob_sas(
            account_name=blob_service_client.account_name,
            container_name=Config.AZURE_CONTAINER_NAME,
            blob_name=blob_name,
            account_key=blob_service_client.credential.account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.datetime.utcnow()
            + datetime.timedelta(hours=1),  # URL valid for 1 hour
        )
        # Generate the file URL with SAS token
        file_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{Config.AZURE_CONTAINER_NAME}/{blob_name}?{sas_token}"
        return file_url
    except Exception as e:
        raise Exception(f"Error generating SAS URL: {str(e)}")


def getImpactBgcolour(impact):
    impact_color = {
        "Negligible": colors.lightgreen,
        "Minor": colors.green,
        "Moderate": colors.yellow,
        "Major": colors.orange,
        "Severe": colors.red,
    }

    return impact_color.get(impact, None)

def getFesRateBgColor(rating):
    rating_color = {
        "Very low": colors.lightgreen,
        "Low": colors.green,
        "Medium": colors.yellow,
        "High": colors.red,
        "Very High": colors.red,
    }
    return rating_color.get(rating,None)