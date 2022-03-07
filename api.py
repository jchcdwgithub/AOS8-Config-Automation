import AOS8_config_automation as CA
from docx import Document

columns = CA.get_columns_from_tables(Document('..\Test Tables.docx').tables[:2])