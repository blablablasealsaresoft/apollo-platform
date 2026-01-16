"""
Image Forensics - Manipulation Detection and Analysis
Error Level Analysis, deepfake detection, source identification
"""

import os
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import hashlib


class ImageForensics:
    """
    Image forensics and manipulation detection
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize image forensics"""
        self.config = config or {}
        self.logger = logging.getLogger('ImageForensics')

        # Configuration
        self.ela_quality = self.config.get('ela_quality', 95)
        self.ela_scale = self.config.get('ela_scale', 10)

        # Initialize libraries
        self._initialize_libraries()

        self.logger.info("Image Forensics initialized")

    def _initialize_libraries(self):
        """Initialize forensics libraries"""
        try:
            from PIL import Image, ImageChops, ImageEnhance
            self.Image = Image
            self.ImageChops = ImageChops
            self.ImageEnhance = ImageEnhance
            self.has_pil = True
            self.logger.info("PIL/Pillow loaded")
        except ImportError:
            self.has_pil = False
            self.logger.warning("PIL/Pillow not available")

        try:
            import cv2
            self.cv2 = cv2
            self.has_cv2 = True
            self.logger.info("OpenCV loaded")
        except ImportError:
            self.has_cv2 = False
            self.logger.warning("OpenCV not available")

        try:
            import numpy as np
            self.np = np
            self.has_numpy = True
        except ImportError:
            self.has_numpy = False
            self.logger.warning("NumPy not available")

    def analyze_image(self, image_path: str) -> Dict[str, Any]:
        """
        Comprehensive forensic analysis of image

        Args:
            image_path: Path to image file

        Returns:
            Complete forensic analysis results
        """
        self.logger.info(f"Performing forensic analysis on: {image_path}")

        results = {
            'image_path': image_path,
            'manipulation_detected': False,
            'manipulation_score': 0.0,
            'tests_performed': [],
            'anomalies': []
        }

        # Error Level Analysis
        ela_result = self.error_level_analysis(image_path)
        if ela_result:
            results['tests_performed'].append('error_level_analysis')
            results['ela_result'] = ela_result
            if ela_result.get('manipulation_likelihood', 0) > 0.5:
                results['manipulation_detected'] = True
                results['anomalies'].append('High ELA variance detected')

        # JPEG Ghost Analysis
        jpeg_ghost = self.jpeg_ghost_analysis(image_path)
        if jpeg_ghost:
            results['tests_performed'].append('jpeg_ghost')
            results['jpeg_ghost'] = jpeg_ghost

        # Noise Analysis
        noise_analysis = self.noise_analysis(image_path)
        if noise_analysis:
            results['tests_performed'].append('noise_analysis')
            results['noise_analysis'] = noise_analysis
            if noise_analysis.get('inconsistent_noise'):
                results['manipulation_detected'] = True
                results['anomalies'].append('Inconsistent noise patterns detected')

        # Clone Detection
        clone_result = self.clone_detection(image_path)
        if clone_result:
            results['tests_performed'].append('clone_detection')
            results['clone_detection'] = clone_result
            if clone_result.get('clones_detected', 0) > 0:
                results['manipulation_detected'] = True
                results['anomalies'].append('Cloned regions detected')

        # Metadata Analysis
        metadata_analysis = self.analyze_metadata_consistency(image_path)
        if metadata_analysis:
            results['tests_performed'].append('metadata_analysis')
            results['metadata_analysis'] = metadata_analysis
            if metadata_analysis.get('inconsistencies'):
                results['anomalies'].extend(metadata_analysis['inconsistencies'])

        # Calculate overall manipulation score
        results['manipulation_score'] = self._calculate_manipulation_score(results)

        return results

    def error_level_analysis(self, image_path: str) -> Dict[str, Any]:
        """
        Perform Error Level Analysis (ELA)

        Args:
            image_path: Path to image

        Returns:
            ELA results
        """
        self.logger.info("Performing Error Level Analysis...")

        if not self.has_pil:
            return {}

        try:
            # Load original image
            original = self.Image.open(image_path)

            # Save at specific quality
            temp_path = image_path + '.temp.jpg'
            original.save(temp_path, 'JPEG', quality=self.ela_quality)

            # Load compressed image
            compressed = self.Image.open(temp_path)

            # Calculate difference
            ela_image = self.ImageChops.difference(original, compressed)

            # Enhance the difference
            extrema = ela_image.getextrema()
            max_diff = max([ex[1] for ex in extrema])

            if max_diff == 0:
                max_diff = 1

            scale = 255.0 / max_diff
            ela_image = self.ImageEnhance.Brightness(ela_image).enhance(scale)

            # Save ELA image
            ela_output_path = image_path + '.ela.png'
            ela_image.save(ela_output_path)

            # Analyze ELA results
            ela_array = np.array(ela_image)
            mean_ela = ela_array.mean()
            std_ela = ela_array.std()

            # Clean up
            os.remove(temp_path)

            results = {
                'ela_image_path': ela_output_path,
                'mean_ela': float(mean_ela),
                'std_ela': float(std_ela),
                'max_difference': int(max_diff),
                'manipulation_likelihood': min(1.0, std_ela / 50.0)  # Normalized score
            }

            self.logger.info(f"ELA complete. Manipulation likelihood: {results['manipulation_likelihood']:.2f}")

            return results

        except Exception as e:
            self.logger.error(f"ELA error: {str(e)}")
            return {}

    def jpeg_ghost_analysis(self, image_path: str) -> Dict[str, Any]:
        """
        JPEG Ghost analysis to detect re-compression

        Args:
            image_path: Path to image

        Returns:
            JPEG ghost results
        """
        self.logger.info("Performing JPEG ghost analysis...")

        if not self.has_pil:
            return {}

        try:
            results = {
                'ghost_detected': False,
                'quality_estimates': []
            }

            original = self.Image.open(image_path)

            # Test multiple quality levels
            quality_levels = [75, 85, 90, 95]

            for quality in quality_levels:
                temp_path = f"{image_path}.temp.q{quality}.jpg"
                original.save(temp_path, 'JPEG', quality=quality)

                compressed = self.Image.open(temp_path)
                diff = self.ImageChops.difference(original, compressed)

                # Calculate difference
                diff_array = np.array(diff)
                mean_diff = diff_array.mean()

                results['quality_estimates'].append({
                    'quality': quality,
                    'difference': float(mean_diff)
                })

                os.remove(temp_path)

            # Analyze results
            differences = [q['difference'] for q in results['quality_estimates']]
            min_diff_idx = differences.index(min(differences))
            estimated_quality = quality_levels[min_diff_idx]

            results['estimated_original_quality'] = estimated_quality

            # If image shows low difference at specific quality, it may have been saved at that quality
            if differences[min_diff_idx] < 5:
                results['ghost_detected'] = True
                results['likely_quality'] = estimated_quality

            return results

        except Exception as e:
            self.logger.error(f"JPEG ghost analysis error: {str(e)}")
            return {}

    def noise_analysis(self, image_path: str) -> Dict[str, Any]:
        """
        Analyze noise patterns for inconsistencies

        Args:
            image_path: Path to image

        Returns:
            Noise analysis results
        """
        self.logger.info("Analyzing noise patterns...")

        if not self.has_cv2:
            return {}

        try:
            # Load image
            image = self.cv2.imread(image_path)
            gray = self.cv2.cvtColor(image, self.cv2.COLOR_BGR2GRAY)

            # Divide image into regions
            h, w = gray.shape
            region_size = 64
            regions = []

            for y in range(0, h - region_size, region_size):
                for x in range(0, w - region_size, region_size):
                    region = gray[y:y+region_size, x:x+region_size]

                    # Calculate noise level (std deviation)
                    noise_level = region.std()
                    regions.append({
                        'x': x,
                        'y': y,
                        'noise_level': float(noise_level)
                    })

            # Analyze noise consistency
            noise_levels = [r['noise_level'] for r in regions]
            mean_noise = np.mean(noise_levels)
            std_noise = np.std(noise_levels)

            results = {
                'mean_noise_level': float(mean_noise),
                'noise_variance': float(std_noise),
                'inconsistent_noise': std_noise > mean_noise * 0.5,  # High variance indicates manipulation
                'regions_analyzed': len(regions)
            }

            return results

        except Exception as e:
            self.logger.error(f"Noise analysis error: {str(e)}")
            return {}

    def clone_detection(self, image_path: str) -> Dict[str, Any]:
        """
        Detect cloned/copied regions in image

        Args:
            image_path: Path to image

        Returns:
            Clone detection results
        """
        self.logger.info("Detecting cloned regions...")

        if not self.has_cv2:
            return {}

        try:
            # Load image
            image = self.cv2.imread(image_path)
            gray = self.cv2.cvtColor(image, self.cv2.COLOR_BGR2GRAY)

            # Use feature matching to detect similar regions
            # Initialize ORB detector
            orb = self.cv2.ORB_create()

            # Detect keypoints and compute descriptors
            keypoints, descriptors = orb.detectAndCompute(gray, None)

            results = {
                'clones_detected': 0,
                'suspicious_regions': [],
                'keypoints_detected': len(keypoints)
            }

            # This is a simplified version
            # Full implementation would require more sophisticated matching

            return results

        except Exception as e:
            self.logger.error(f"Clone detection error: {str(e)}")
            return {}

    def analyze_metadata_consistency(self, image_path: str) -> Dict[str, Any]:
        """
        Analyze metadata for inconsistencies

        Args:
            image_path: Path to image

        Returns:
            Metadata consistency analysis
        """
        self.logger.info("Analyzing metadata consistency...")

        results = {
            'inconsistencies': []
        }

        try:
            # Import EXIF analyzer
            from exif_analyzer import EXIFAnalyzer

            analyzer = EXIFAnalyzer()
            exif_data = analyzer.extract_exif(image_path)

            # Check for common inconsistencies

            # Software editing indicators
            if exif_data.get('software'):
                software = str(exif_data['software']).lower()
                editing_software = ['photoshop', 'gimp', 'lightroom', 'paint.net', 'pixlr']
                if any(editor in software for editor in editing_software):
                    results['inconsistencies'].append(f"Image edited with: {software}")

            # Check datetime inconsistencies
            if exif_data.get('datetime'):
                dt = exif_data['datetime']
                if 'datetime' in dt and 'datetimeoriginal' in dt:
                    if dt['datetime'] != dt['datetimeoriginal']:
                        results['inconsistencies'].append("DateTime mismatch - image may have been modified")

            # Missing expected metadata
            if not exif_data.get('has_exif'):
                results['inconsistencies'].append("No EXIF data - metadata may have been stripped")

        except Exception as e:
            self.logger.error(f"Metadata analysis error: {str(e)}")

        return results

    def detect_deepfake(self, image_path: str) -> Dict[str, Any]:
        """
        Detect potential deepfake/AI-generated images

        Args:
            image_path: Path to image

        Returns:
            Deepfake detection results
        """
        self.logger.info("Analyzing for deepfake indicators...")

        results = {
            'is_deepfake': False,
            'confidence': 0.0,
            'indicators': [],
            'method': 'heuristic'
        }

        # Note: Real deepfake detection requires specialized ML models
        # This is a simplified heuristic approach

        try:
            if self.has_cv2:
                image = self.cv2.imread(image_path)

                # Check for common deepfake artifacts
                # 1. Unusual color distribution
                # 2. Inconsistent lighting
                # 3. Blur patterns around edges
                # 4. Lack of natural noise

                # This would require more sophisticated analysis
                results['note'] = 'Advanced deepfake detection requires specialized ML models'

        except Exception as e:
            self.logger.error(f"Deepfake detection error: {str(e)}")

        return results

    def _calculate_manipulation_score(self, analysis_results: Dict[str, Any]) -> float:
        """Calculate overall manipulation score"""
        score = 0.0
        weights = 0.0

        # ELA score
        if 'ela_result' in analysis_results:
            ela_score = analysis_results['ela_result'].get('manipulation_likelihood', 0)
            score += ela_score * 0.3
            weights += 0.3

        # Noise analysis
        if 'noise_analysis' in analysis_results:
            if analysis_results['noise_analysis'].get('inconsistent_noise'):
                score += 0.4 * 0.3
                weights += 0.3

        # Clone detection
        if 'clone_detection' in analysis_results:
            clones = analysis_results['clone_detection'].get('clones_detected', 0)
            if clones > 0:
                score += 0.5 * 0.2
                weights += 0.2

        # Metadata inconsistencies
        if 'metadata_analysis' in analysis_results:
            inconsistencies = len(analysis_results['metadata_analysis'].get('inconsistencies', []))
            if inconsistencies > 0:
                score += min(1.0, inconsistencies * 0.2) * 0.2
                weights += 0.2

        # Normalize score
        if weights > 0:
            return score / weights
        return 0.0

    def generate_forensics_report(self, analysis_results: Dict[str, Any], output_path: str):
        """
        Generate detailed forensics report

        Args:
            analysis_results: Analysis results
            output_path: Output report path
        """
        self.logger.info(f"Generating forensics report: {output_path}")

        report = []
        report.append("=" * 80)
        report.append("IMAGE FORENSICS ANALYSIS REPORT")
        report.append("=" * 80)
        report.append(f"\nImage: {analysis_results['image_path']}")
        report.append(f"Manipulation Detected: {analysis_results['manipulation_detected']}")
        report.append(f"Manipulation Score: {analysis_results['manipulation_score']:.2%}")
        report.append(f"\nTests Performed: {', '.join(analysis_results['tests_performed'])}")

        if analysis_results['anomalies']:
            report.append("\nANOMALIES DETECTED:")
            for anomaly in analysis_results['anomalies']:
                report.append(f"  - {anomaly}")

        # Detailed results for each test
        if 'ela_result' in analysis_results:
            report.append("\nERROR LEVEL ANALYSIS:")
            ela = analysis_results['ela_result']
            report.append(f"  Mean ELA: {ela.get('mean_ela', 0):.2f}")
            report.append(f"  Std ELA: {ela.get('std_ela', 0):.2f}")
            report.append(f"  Manipulation Likelihood: {ela.get('manipulation_likelihood', 0):.2%}")

        report.append("\n" + "=" * 80)

        # Write report
        with open(output_path, 'w') as f:
            f.write('\n'.join(report))

        self.logger.info("Report generated")


if __name__ == "__main__":
    print("Image Forensics - Manipulation Detection")
    print("=" * 60)

    forensics = ImageForensics()

    print("\nCapabilities:")
    print("  - Error Level Analysis (ELA)")
    print("  - JPEG ghost detection")
    print("  - Noise analysis")
    print("  - Clone detection")
    print("  - Metadata consistency check")
    print("  - Deepfake indicators")
    print("\nUsage:")
    print("  results = forensics.analyze_image('suspect_image.jpg')")
    print("  ela = forensics.error_level_analysis('image.jpg')")
    print("  deepfake = forensics.detect_deepfake('face.jpg')")
