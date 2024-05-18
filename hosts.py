import gspread
gc = gspread.service_account(filename='yourJson file')
wks = gc.open("yourSheet").sheet1




