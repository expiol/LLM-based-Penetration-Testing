from datetime import datetime


def str_to_seconds(time_str):
    if time_str:
        datetime_object = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        timestamp_seconds = datetime_object.timestamp()
        return int(timestamp_seconds)
    else:
        return 0


