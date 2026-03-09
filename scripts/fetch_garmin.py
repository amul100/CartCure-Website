"""
Fetch recent Garmin Connect activities for the Double As team.
Writes activity summaries to DoubleAs/garmin-data.json.

Requires environment variables:
  GARMIN_EMAIL_ANDREW, GARMIN_PASSWORD_ANDREW
  GARMIN_EMAIL_AMANDA, GARMIN_PASSWORD_AMANDA
"""

import json
import os
import sys
from datetime import datetime, timezone

from garminconnect import Garmin


def format_duration(seconds):
    """Convert seconds to H:MM:SS or M:SS format."""
    if not seconds:
        return "0:00"
    hours = int(seconds // 3600)
    mins = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    if hours > 0:
        return f"{hours}:{mins:02d}:{secs:02d}"
    return f"{mins}:{secs:02d}"


def format_pace(speed_mps, activity_type):
    """Convert m/s to min/km (run/swim) or km/h (bike)."""
    if not speed_mps or speed_mps == 0:
        return ""
    if activity_type == "cycling":
        kmh = speed_mps * 3.6
        return f"{kmh:.1f} km/h"
    else:
        # min/km for run and swim
        pace_seconds = 1000 / speed_mps
        mins = int(pace_seconds // 60)
        secs = int(pace_seconds % 60)
        return f"{mins}:{secs:02d} /km"


def classify_activity(activity_type_key):
    """Map Garmin activity type to our categories."""
    cycling_types = {"cycling", "road_biking", "mountain_biking", "indoor_cycling",
                     "virtual_ride", "gravel_cycling", "cyclocross", "bike"}
    swimming_types = {"swimming", "open_water_swimming", "pool_swimming", "lap_swimming"}
    running_types = {"running", "trail_running", "treadmill_running", "indoor_running",
                     "track_running", "virtual_run"}

    key = activity_type_key.lower().replace(" ", "_")

    if key in cycling_types or "cycling" in key or "biking" in key or "bike" in key:
        return "cycling"
    if key in swimming_types or "swim" in key:
        return "swimming"
    if key in running_types or "run" in key:
        return "running"
    return None


def fetch_activities(email, password, athlete_name, max_activities=20):
    """Fetch recent activities from Garmin Connect."""
    print(f"  Logging in as {athlete_name}...")
    client = Garmin(email, password)
    client.login()

    print(f"  Fetching activities...")
    raw = client.get_activities(0, max_activities)

    activities = {"cycling": [], "swimming": [], "running": []}

    for act in raw:
        activity_type_key = act.get("activityType", {}).get("typeKey", "")
        category = classify_activity(activity_type_key)
        if not category:
            continue

        distance_km = (act.get("distance") or 0) / 1000
        duration_secs = act.get("duration") or 0
        avg_speed = act.get("averageSpeed") or 0
        avg_hr = act.get("averageHR")
        max_hr = act.get("maxHR")
        elevation = act.get("elevationGain")
        calories = act.get("calories")
        start_time = act.get("startTimeLocal", "")

        activity_data = {
            "name": act.get("activityName", "Untitled"),
            "date": start_time[:10] if start_time else "",
            "distance": round(distance_km, 2),
            "duration": format_duration(duration_secs),
            "durationSeconds": int(duration_secs),
            "pace": format_pace(avg_speed, category),
            "avgHR": int(avg_hr) if avg_hr else None,
            "maxHR": int(max_hr) if max_hr else None,
            "elevation": int(elevation) if elevation else None,
            "calories": int(calories) if calories else None,
            "type": category,
        }

        activities[category].append(activity_data)

    for cat in activities:
        activities[cat] = activities[cat][:5]  # Keep latest 5 per category

    total = sum(len(v) for v in activities.values())
    print(f"  Found {total} relevant activities for {athlete_name}")
    return activities


def main():
    output_path = os.path.join(os.path.dirname(__file__), "..", "DoubleAs", "garmin-data.json")

    data = {
        "lastUpdated": datetime.now(timezone.utc).isoformat(),
        "andrew": {"cycling": [], "swimming": [], "running": []},
        "amanda": {"cycling": [], "swimming": [], "running": []},
    }

    # Fetch Andrew's activities
    andrew_email = os.environ.get("GARMIN_EMAIL_ANDREW")
    andrew_pass = os.environ.get("GARMIN_PASSWORD_ANDREW")
    if andrew_email and andrew_pass:
        try:
            print("Fetching Andrew's activities...")
            data["andrew"] = fetch_activities(andrew_email, andrew_pass, "Andrew")
        except Exception as e:
            print(f"  ERROR fetching Andrew's data: {e}", file=sys.stderr)
    else:
        print("Skipping Andrew (no credentials)")

    # Fetch Amanda's activities
    amanda_email = os.environ.get("GARMIN_EMAIL_AMANDA")
    amanda_pass = os.environ.get("GARMIN_PASSWORD_AMANDA")
    if amanda_email and amanda_pass:
        try:
            print("Fetching Amanda's activities...")
            data["amanda"] = fetch_activities(amanda_email, amanda_pass, "Amanda")
        except Exception as e:
            print(f"  ERROR fetching Amanda's data: {e}", file=sys.stderr)
    else:
        print("Skipping Amanda (no credentials)")

    # Write JSON
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nWrote garmin-data.json ({os.path.getsize(output_path)} bytes)")


if __name__ == "__main__":
    main()
