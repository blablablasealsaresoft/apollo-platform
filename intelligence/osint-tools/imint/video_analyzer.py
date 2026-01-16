"""
Video Analyzer - Comprehensive Video Intelligence
Frame extraction, scene detection, audio analysis, YouTube OSINT
"""

import os
import logging
import subprocess
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import json


class VideoAnalyzer:
    """
    Comprehensive video analysis for IMINT operations
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize video analyzer"""
        self.config = config or {}
        self.logger = logging.getLogger('VideoAnalyzer')

        # Configuration
        self.frames_per_second = self.config.get('frames_per_second', 1)
        self.max_frames = self.config.get('max_frames', 100)
        self.output_dir = self.config.get('output_dir', 'video_analysis')

        # Initialize libraries
        self._initialize_libraries()

        self.logger.info("Video Analyzer initialized")

    def _initialize_libraries(self):
        """Initialize video processing libraries"""
        try:
            import cv2
            self.cv2 = cv2
            self.has_cv2 = True
            self.logger.info("OpenCV loaded")
        except ImportError:
            self.has_cv2 = False
            self.logger.warning("OpenCV not available")

        try:
            # Check for ffmpeg
            result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.has_ffmpeg = True
                self.logger.info("FFmpeg available")
            else:
                self.has_ffmpeg = False
        except FileNotFoundError:
            self.has_ffmpeg = False
            self.logger.warning("FFmpeg not available")

        try:
            # Check for youtube-dl or yt-dlp
            result = subprocess.run(['yt-dlp', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.has_ytdlp = True
                self.youtube_downloader = 'yt-dlp'
                self.logger.info("yt-dlp available")
            else:
                result = subprocess.run(['youtube-dl', '--version'], capture_output=True, text=True)
                if result.returncode == 0:
                    self.has_ytdlp = True
                    self.youtube_downloader = 'youtube-dl'
                    self.logger.info("youtube-dl available")
                else:
                    self.has_ytdlp = False
        except FileNotFoundError:
            self.has_ytdlp = False
            self.logger.warning("yt-dlp/youtube-dl not available")

    def extract_metadata(self, video_path: str) -> Dict[str, Any]:
        """
        Extract video metadata

        Args:
            video_path: Path to video file

        Returns:
            Video metadata
        """
        self.logger.info(f"Extracting metadata from: {video_path}")

        metadata = {
            'file_path': video_path,
            'file_name': os.path.basename(video_path),
            'file_size': os.path.getsize(video_path),
            'duration': None,
            'fps': None,
            'frame_count': None,
            'resolution': None,
            'codec': None,
            'bitrate': None
        }

        if self.has_cv2:
            try:
                cap = self.cv2.VideoCapture(video_path)

                metadata['fps'] = cap.get(self.cv2.CAP_PROP_FPS)
                metadata['frame_count'] = int(cap.get(self.cv2.CAP_PROP_FRAME_COUNT))
                metadata['width'] = int(cap.get(self.cv2.CAP_PROP_FRAME_WIDTH))
                metadata['height'] = int(cap.get(self.cv2.CAP_PROP_FRAME_HEIGHT))
                metadata['resolution'] = f"{metadata['width']}x{metadata['height']}"

                if metadata['fps'] > 0:
                    metadata['duration'] = metadata['frame_count'] / metadata['fps']
                    metadata['duration_formatted'] = str(timedelta(seconds=int(metadata['duration'])))

                cap.release()

            except Exception as e:
                self.logger.error(f"Error extracting metadata with OpenCV: {str(e)}")

        # Try ffprobe for more detailed metadata
        if self.has_ffmpeg:
            try:
                ffprobe_metadata = self._extract_metadata_ffprobe(video_path)
                metadata.update(ffprobe_metadata)
            except Exception as e:
                self.logger.error(f"Error extracting metadata with ffprobe: {str(e)}")

        return metadata

    def _extract_metadata_ffprobe(self, video_path: str) -> Dict[str, Any]:
        """Extract metadata using ffprobe"""
        cmd = [
            'ffprobe',
            '-v', 'quiet',
            '-print_format', 'json',
            '-show_format',
            '-show_streams',
            video_path
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            data = json.loads(result.stdout)

            metadata = {}

            # Format information
            if 'format' in data:
                fmt = data['format']
                metadata['codec'] = fmt.get('format_name')
                metadata['bitrate'] = int(fmt.get('bit_rate', 0))
                metadata['creation_time'] = fmt.get('tags', {}).get('creation_time')

            # Stream information
            if 'streams' in data:
                for stream in data['streams']:
                    if stream.get('codec_type') == 'video':
                        metadata['video_codec'] = stream.get('codec_name')
                        metadata['video_bitrate'] = stream.get('bit_rate')
                    elif stream.get('codec_type') == 'audio':
                        metadata['audio_codec'] = stream.get('codec_name')
                        metadata['audio_bitrate'] = stream.get('bit_rate')
                        metadata['audio_sample_rate'] = stream.get('sample_rate')

            return metadata

        return {}

    def extract_key_frames(self, video_path: str, method: str = 'interval') -> List[str]:
        """
        Extract key frames from video

        Args:
            video_path: Path to video file
            method: Extraction method ('interval', 'scene_change', 'uniform')

        Returns:
            List of extracted frame paths
        """
        self.logger.info(f"Extracting key frames from: {video_path}")

        if not self.has_cv2:
            raise Exception("OpenCV required for frame extraction")

        # Create output directory
        video_name = Path(video_path).stem
        output_dir = os.path.join(self.output_dir, f"{video_name}_frames")
        os.makedirs(output_dir, exist_ok=True)

        frame_paths = []

        try:
            cap = self.cv2.VideoCapture(video_path)
            fps = cap.get(self.cv2.CAP_PROP_FPS)
            total_frames = int(cap.get(self.cv2.CAP_PROP_FRAME_COUNT))

            if method == 'interval':
                # Extract at specified FPS interval
                frame_interval = int(fps / self.frames_per_second)
                frame_numbers = range(0, total_frames, frame_interval)[:self.max_frames]

            elif method == 'uniform':
                # Extract uniformly distributed frames
                frame_numbers = [int(i * total_frames / self.max_frames) for i in range(self.max_frames)]

            else:
                frame_numbers = range(0, total_frames, int(fps))[:self.max_frames]

            # Extract frames
            for frame_num in frame_numbers:
                cap.set(self.cv2.CAP_PROP_POS_FRAMES, frame_num)
                ret, frame = cap.read()

                if ret:
                    frame_filename = f"frame_{frame_num:06d}.jpg"
                    frame_path = os.path.join(output_dir, frame_filename)
                    self.cv2.imwrite(frame_path, frame)
                    frame_paths.append(frame_path)

            cap.release()

            self.logger.info(f"Extracted {len(frame_paths)} frames to {output_dir}")

        except Exception as e:
            self.logger.error(f"Frame extraction error: {str(e)}")

        return frame_paths

    def detect_scenes(self, video_path: str, threshold: float = 30.0) -> List[Dict[str, Any]]:
        """
        Detect scene changes in video

        Args:
            video_path: Path to video file
            threshold: Scene change detection threshold

        Returns:
            List of detected scenes with timestamps
        """
        self.logger.info(f"Detecting scenes in: {video_path}")

        scenes = []

        if not self.has_cv2:
            self.logger.warning("OpenCV required for scene detection")
            return scenes

        try:
            cap = self.cv2.VideoCapture(video_path)
            fps = cap.get(self.cv2.CAP_PROP_FPS)

            prev_frame = None
            frame_num = 0
            scene_num = 0

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                # Convert to grayscale
                gray = self.cv2.cvtColor(frame, self.cv2.COLOR_BGR2GRAY)

                if prev_frame is not None:
                    # Calculate frame difference
                    diff = self.cv2.absdiff(prev_frame, gray)
                    mean_diff = diff.mean()

                    # Detect scene change
                    if mean_diff > threshold:
                        timestamp = frame_num / fps
                        scenes.append({
                            'scene_number': scene_num,
                            'frame_number': frame_num,
                            'timestamp': timestamp,
                            'timestamp_formatted': str(timedelta(seconds=int(timestamp))),
                            'difference_score': mean_diff
                        })
                        scene_num += 1

                prev_frame = gray
                frame_num += 1

            cap.release()

            self.logger.info(f"Detected {len(scenes)} scene changes")

        except Exception as e:
            self.logger.error(f"Scene detection error: {str(e)}")

        return scenes

    def extract_audio(self, video_path: str, output_format: str = 'wav') -> Optional[str]:
        """
        Extract audio from video

        Args:
            video_path: Path to video file
            output_format: Audio format (wav, mp3, etc.)

        Returns:
            Path to extracted audio file
        """
        self.logger.info(f"Extracting audio from: {video_path}")

        if not self.has_ffmpeg:
            self.logger.warning("FFmpeg required for audio extraction")
            return None

        try:
            # Create output path
            video_name = Path(video_path).stem
            output_dir = os.path.join(self.output_dir, f"{video_name}_audio")
            os.makedirs(output_dir, exist_ok=True)

            audio_path = os.path.join(output_dir, f"audio.{output_format}")

            # Extract audio with ffmpeg
            cmd = [
                'ffmpeg',
                '-i', video_path,
                '-vn',  # No video
                '-acodec', 'pcm_s16le' if output_format == 'wav' else 'libmp3lame',
                '-y',  # Overwrite
                audio_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                self.logger.info(f"Audio extracted to: {audio_path}")
                return audio_path
            else:
                self.logger.error(f"Audio extraction failed: {result.stderr}")
                return None

        except Exception as e:
            self.logger.error(f"Audio extraction error: {str(e)}")
            return None

    def analyze_youtube_video(self, video_url: str) -> Dict[str, Any]:
        """
        Analyze YouTube video with metadata and content

        Args:
            video_url: YouTube video URL

        Returns:
            Complete YouTube video intelligence
        """
        self.logger.info(f"Analyzing YouTube video: {video_url}")

        results = {
            'url': video_url,
            'metadata': {},
            'video_path': None,
            'frames': [],
            'error': None
        }

        if not self.has_ytdlp:
            results['error'] = 'yt-dlp or youtube-dl not available'
            return results

        try:
            # Extract metadata
            metadata = self._get_youtube_metadata(video_url)
            results['metadata'] = metadata

            # Download video
            if self.config.get('download_youtube_videos', False):
                video_path = self._download_youtube_video(video_url)
                results['video_path'] = video_path

                # Analyze downloaded video
                if video_path:
                    results['frames'] = self.extract_key_frames(video_path)
                    results['scenes'] = self.detect_scenes(video_path)

        except Exception as e:
            self.logger.error(f"YouTube analysis error: {str(e)}")
            results['error'] = str(e)

        return results

    def _get_youtube_metadata(self, video_url: str) -> Dict[str, Any]:
        """Extract YouTube video metadata"""
        cmd = [
            self.youtube_downloader,
            '--dump-json',
            '--no-download',
            video_url
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            metadata = json.loads(result.stdout)

            return {
                'title': metadata.get('title'),
                'description': metadata.get('description'),
                'uploader': metadata.get('uploader'),
                'upload_date': metadata.get('upload_date'),
                'view_count': metadata.get('view_count'),
                'like_count': metadata.get('like_count'),
                'duration': metadata.get('duration'),
                'thumbnail': metadata.get('thumbnail'),
                'tags': metadata.get('tags', []),
                'categories': metadata.get('categories', []),
                'channel_id': metadata.get('channel_id'),
                'channel_url': metadata.get('channel_url')
            }

        return {}

    def _download_youtube_video(self, video_url: str) -> Optional[str]:
        """Download YouTube video"""
        output_dir = os.path.join(self.output_dir, 'youtube_videos')
        os.makedirs(output_dir, exist_ok=True)

        output_template = os.path.join(output_dir, '%(title)s.%(ext)s')

        cmd = [
            self.youtube_downloader,
            '-f', 'best',
            '-o', output_template,
            video_url
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            # Find downloaded file
            files = list(Path(output_dir).glob('*'))
            if files:
                video_path = str(files[-1])
                self.logger.info(f"Video downloaded to: {video_path}")
                return video_path

        return None

    def create_video_thumbnail(self, video_path: str, timestamp: float = 0) -> Optional[str]:
        """
        Create thumbnail from video at specific timestamp

        Args:
            video_path: Path to video
            timestamp: Timestamp in seconds

        Returns:
            Path to thumbnail image
        """
        if not self.has_cv2:
            return None

        try:
            cap = self.cv2.VideoCapture(video_path)
            cap.set(self.cv2.CAP_PROP_POS_MSEC, timestamp * 1000)

            ret, frame = cap.read()
            cap.release()

            if ret:
                video_name = Path(video_path).stem
                thumbnail_path = os.path.join(self.output_dir, f"{video_name}_thumbnail.jpg")
                self.cv2.imwrite(thumbnail_path, frame)
                return thumbnail_path

        except Exception as e:
            self.logger.error(f"Thumbnail creation error: {str(e)}")

        return None


if __name__ == "__main__":
    print("Video Analyzer - Video Intelligence System")
    print("=" * 60)

    analyzer = VideoAnalyzer()

    print("\nCapabilities:")
    print("  - Video metadata extraction")
    print("  - Key frame extraction")
    print("  - Scene detection")
    print("  - Audio extraction")
    print("  - YouTube video OSINT")
    print("\nUsage:")
    print("  metadata = analyzer.extract_metadata('video.mp4')")
    print("  frames = analyzer.extract_key_frames('video.mp4')")
    print("  scenes = analyzer.detect_scenes('video.mp4')")
    print("  audio = analyzer.extract_audio('video.mp4')")
    print("  yt_data = analyzer.analyze_youtube_video('https://youtube.com/watch?v=...')")
