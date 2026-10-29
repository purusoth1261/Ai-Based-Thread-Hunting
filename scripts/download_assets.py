from pathlib import Path
from huggingface_hub import hf_hub_download

REPO_ID = "purusoth1261/thread-hunting-assets"
ROOT = Path(__file__).resolve().parent.parent

ASSETS = {
    "models": [
        "modeladvlatest.pkl",
        "final_model2normal.pkl",
        "label_encoderlatest.pkl",
        "label_encoder21normal.pkl",
    ],
    "data": [
        "network_data Model2.csv",
        "network_traffic Model1.xlsx",
    ],
}


def main():
    for folder, filenames in ASSETS.items():
        target_dir = ROOT / folder
        target_dir.mkdir(parents=True, exist_ok=True)

        for filename in filenames:
            print(f"\nDownloading/checking {filename} ...")
            path = hf_hub_download(
                repo_id=REPO_ID,
                filename=filename,
                local_dir=str(target_dir),
            )
            print(f"Ready: {path}")

    print("\nAll project assets are ready.")


if __name__ == "__main__":
    main()