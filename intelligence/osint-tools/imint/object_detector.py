"""
Object Detector - Advanced Object Recognition
YOLO detection, landmarks, vehicles, brands, logos
"""

import os
import logging
import numpy as np
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path


class ObjectDetector:
    """
    Advanced object detection for IMINT operations
    """

    def __init__(self, config: Optional[Dict] = None):
        """Initialize object detector"""
        self.config = config or {}
        self.logger = logging.getLogger('ObjectDetector')

        # Configuration
        self.confidence_threshold = self.config.get('confidence_threshold', 0.5)
        self.nms_threshold = self.config.get('nms_threshold', 0.4)

        # Initialize detection models
        self._initialize_models()

        self.logger.info("Object Detector initialized")

    def _initialize_models(self):
        """Initialize object detection models"""
        self.models_available = {}

        # Try to load YOLO with OpenCV
        try:
            import cv2
            self.cv2 = cv2
            self.has_cv2 = True

            # Try to load YOLOv3/YOLOv4 weights
            yolo_config = self.config.get('yolo_config', 'yolov3.cfg')
            yolo_weights = self.config.get('yolo_weights', 'yolov3.weights')
            yolo_names = self.config.get('yolo_names', 'coco.names')

            if os.path.exists(yolo_weights) and os.path.exists(yolo_config):
                self.yolo_net = cv2.dnn.readNet(yolo_weights, yolo_config)
                self.yolo_net.setPreferableBackend(cv2.dnn.DNN_BACKEND_OPENCV)
                self.yolo_net.setPreferableTarget(cv2.dnn.DNN_TARGET_CPU)

                # Load class names
                if os.path.exists(yolo_names):
                    with open(yolo_names, 'r') as f:
                        self.yolo_classes = [line.strip() for line in f.readlines()]
                else:
                    self.yolo_classes = self._get_default_coco_classes()

                self.models_available['yolo'] = True
                self.logger.info("YOLO model loaded")
            else:
                self.models_available['yolo'] = False
                self.logger.warning("YOLO weights not found")

        except ImportError:
            self.has_cv2 = False
            self.models_available['yolo'] = False
            self.logger.warning("OpenCV not available")

        # Try to load TensorFlow/Keras models
        try:
            import tensorflow as tf
            self.tf = tf
            self.has_tensorflow = True
            self.models_available['tensorflow'] = True
            self.logger.info("TensorFlow available")
        except ImportError:
            self.has_tensorflow = False
            self.models_available['tensorflow'] = False
            self.logger.warning("TensorFlow not available")

        # Try to load PyTorch models
        try:
            import torch
            self.torch = torch
            self.has_torch = True
            self.models_available['torch'] = True
            self.logger.info("PyTorch available")
        except ImportError:
            self.has_torch = False
            self.models_available['torch'] = False
            self.logger.warning("PyTorch not available")

    def detect_objects(self, image_path: str) -> Dict[str, Any]:
        """
        Detect objects in image

        Args:
            image_path: Path to image

        Returns:
            Detected objects with bounding boxes and confidence
        """
        self.logger.info(f"Detecting objects in: {image_path}")

        results = {
            'image_path': image_path,
            'detected_objects': [],
            'total_objects': 0,
            'categories': {},
            'detection_method': None
        }

        # Try YOLO first
        if self.models_available.get('yolo'):
            results = self._detect_with_yolo(image_path)

        # Try TensorFlow object detection
        elif self.models_available.get('tensorflow'):
            results = self._detect_with_tensorflow(image_path)

        # Try PyTorch/Torchvision
        elif self.models_available.get('torch'):
            results = self._detect_with_torch(image_path)

        # Categorize objects
        results['categories'] = self._categorize_objects(results['detected_objects'])
        results['total_objects'] = len(results['detected_objects'])

        return results

    def _detect_with_yolo(self, image_path: str) -> Dict[str, Any]:
        """Detect objects using YOLO"""
        results = {
            'image_path': image_path,
            'detected_objects': [],
            'detection_method': 'YOLO'
        }

        try:
            # Load image
            image = self.cv2.imread(image_path)
            height, width = image.shape[:2]

            # Create blob
            blob = self.cv2.dnn.blobFromImage(
                image, 1/255.0, (416, 416), swapRB=True, crop=False
            )

            # Forward pass
            self.yolo_net.setInput(blob)
            layer_names = self.yolo_net.getLayerNames()
            output_layers = [layer_names[i - 1] for i in self.yolo_net.getUnconnectedOutLayers()]
            outputs = self.yolo_net.forward(output_layers)

            # Process detections
            boxes = []
            confidences = []
            class_ids = []

            for output in outputs:
                for detection in output:
                    scores = detection[5:]
                    class_id = np.argmax(scores)
                    confidence = scores[class_id]

                    if confidence > self.confidence_threshold:
                        # Get bounding box coordinates
                        center_x = int(detection[0] * width)
                        center_y = int(detection[1] * height)
                        w = int(detection[2] * width)
                        h = int(detection[3] * height)
                        x = int(center_x - w / 2)
                        y = int(center_y - h / 2)

                        boxes.append([x, y, w, h])
                        confidences.append(float(confidence))
                        class_ids.append(class_id)

            # Apply NMS
            indices = self.cv2.dnn.NMSBoxes(
                boxes, confidences, self.confidence_threshold, self.nms_threshold
            )

            # Format results
            if len(indices) > 0:
                for i in indices.flatten():
                    box = boxes[i]
                    class_id = class_ids[i]
                    confidence = confidences[i]

                    results['detected_objects'].append({
                        'class': self.yolo_classes[class_id],
                        'class_id': int(class_id),
                        'confidence': confidence,
                        'bounding_box': {
                            'x': box[0],
                            'y': box[1],
                            'width': box[2],
                            'height': box[3]
                        },
                        'category': self._get_object_category(self.yolo_classes[class_id])
                    })

            self.logger.info(f"YOLO detected {len(results['detected_objects'])} objects")

        except Exception as e:
            self.logger.error(f"YOLO detection error: {str(e)}")

        return results

    def _detect_with_tensorflow(self, image_path: str) -> Dict[str, Any]:
        """Detect objects using TensorFlow"""
        results = {
            'image_path': image_path,
            'detected_objects': [],
            'detection_method': 'TensorFlow'
        }

        try:
            # Load pre-trained model (example: MobileNet SSD)
            # This would need the actual model file
            self.logger.info("TensorFlow object detection not fully implemented")

        except Exception as e:
            self.logger.error(f"TensorFlow detection error: {str(e)}")

        return results

    def _detect_with_torch(self, image_path: str) -> Dict[str, Any]:
        """Detect objects using PyTorch"""
        results = {
            'image_path': image_path,
            'detected_objects': [],
            'detection_method': 'PyTorch'
        }

        try:
            import torchvision
            from PIL import Image

            # Load pre-trained Faster R-CNN
            model = torchvision.models.detection.fasterrcnn_resnet50_fpn(pretrained=True)
            model.eval()

            # Load and preprocess image
            image = Image.open(image_path).convert('RGB')
            transform = torchvision.transforms.Compose([
                torchvision.transforms.ToTensor()
            ])
            image_tensor = transform(image).unsqueeze(0)

            # Detect
            with self.torch.no_grad():
                predictions = model(image_tensor)[0]

            # COCO class names
            coco_classes = self._get_default_coco_classes()

            # Process predictions
            for i in range(len(predictions['boxes'])):
                score = predictions['scores'][i].item()

                if score > self.confidence_threshold:
                    box = predictions['boxes'][i].cpu().numpy()
                    label_idx = predictions['labels'][i].item()

                    results['detected_objects'].append({
                        'class': coco_classes[label_idx] if label_idx < len(coco_classes) else f'class_{label_idx}',
                        'class_id': label_idx,
                        'confidence': score,
                        'bounding_box': {
                            'x': int(box[0]),
                            'y': int(box[1]),
                            'width': int(box[2] - box[0]),
                            'height': int(box[3] - box[1])
                        },
                        'category': self._get_object_category(coco_classes[label_idx] if label_idx < len(coco_classes) else 'unknown')
                    })

            self.logger.info(f"PyTorch detected {len(results['detected_objects'])} objects")

        except Exception as e:
            self.logger.error(f"PyTorch detection error: {str(e)}")

        return results

    def detect_vehicles(self, image_path: str) -> List[Dict[str, Any]]:
        """
        Detect vehicles specifically

        Args:
            image_path: Path to image

        Returns:
            List of detected vehicles
        """
        all_objects = self.detect_objects(image_path)

        vehicle_classes = ['car', 'truck', 'bus', 'motorcycle', 'bicycle', 'train', 'airplane', 'boat']

        vehicles = [
            obj for obj in all_objects['detected_objects']
            if obj['class'].lower() in vehicle_classes
        ]

        self.logger.info(f"Detected {len(vehicles)} vehicles")

        return vehicles

    def detect_weapons(self, image_path: str) -> List[Dict[str, Any]]:
        """
        Detect weapons in image

        Args:
            image_path: Path to image

        Returns:
            List of detected weapons
        """
        all_objects = self.detect_objects(image_path)

        weapon_classes = ['knife', 'gun', 'rifle', 'weapon']

        weapons = [
            obj for obj in all_objects['detected_objects']
            if obj['class'].lower() in weapon_classes or 'weapon' in obj.get('category', '').lower()
        ]

        self.logger.info(f"Detected {len(weapons)} weapons")

        return weapons

    def detect_landmarks(self, image_path: str) -> Dict[str, Any]:
        """
        Detect landmarks in image

        Args:
            image_path: Path to image

        Returns:
            Detected landmarks
        """
        results = {
            'image_path': image_path,
            'landmarks': [],
            'method': 'visual_recognition'
        }

        # This would integrate with Google Vision API or similar
        # for landmark detection
        self.logger.info("Landmark detection requires external API integration")

        return results

    def detect_logos_brands(self, image_path: str) -> List[Dict[str, Any]]:
        """
        Detect logos and brands in image

        Args:
            image_path: Path to image

        Returns:
            Detected logos and brands
        """
        logos = []

        # This would use specialized logo detection models
        self.logger.info("Logo/brand detection requires specialized models")

        return logos

    def _categorize_objects(self, objects: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize detected objects"""
        categories = {}

        for obj in objects:
            category = obj.get('category', 'unknown')
            categories[category] = categories.get(category, 0) + 1

        return categories

    def _get_object_category(self, class_name: str) -> str:
        """Get category for object class"""
        class_name = class_name.lower()

        if class_name in ['person', 'man', 'woman', 'child']:
            return 'person'
        elif class_name in ['car', 'truck', 'bus', 'motorcycle', 'bicycle', 'train', 'airplane', 'boat']:
            return 'vehicle'
        elif class_name in ['dog', 'cat', 'bird', 'horse', 'cow', 'elephant', 'bear', 'zebra', 'giraffe']:
            return 'animal'
        elif class_name in ['knife', 'gun', 'rifle', 'weapon']:
            return 'weapon'
        elif class_name in ['phone', 'laptop', 'keyboard', 'mouse', 'tv', 'monitor']:
            return 'electronics'
        elif class_name in ['building', 'house', 'bridge', 'tower']:
            return 'structure'
        else:
            return 'other'

    def _get_default_coco_classes(self) -> List[str]:
        """Get COCO dataset class names"""
        return [
            'person', 'bicycle', 'car', 'motorcycle', 'airplane', 'bus', 'train', 'truck', 'boat',
            'traffic light', 'fire hydrant', 'stop sign', 'parking meter', 'bench', 'bird', 'cat',
            'dog', 'horse', 'sheep', 'cow', 'elephant', 'bear', 'zebra', 'giraffe', 'backpack',
            'umbrella', 'handbag', 'tie', 'suitcase', 'frisbee', 'skis', 'snowboard', 'sports ball',
            'kite', 'baseball bat', 'baseball glove', 'skateboard', 'surfboard', 'tennis racket',
            'bottle', 'wine glass', 'cup', 'fork', 'knife', 'spoon', 'bowl', 'banana', 'apple',
            'sandwich', 'orange', 'broccoli', 'carrot', 'hot dog', 'pizza', 'donut', 'cake', 'chair',
            'couch', 'potted plant', 'bed', 'dining table', 'toilet', 'tv', 'laptop', 'mouse',
            'remote', 'keyboard', 'cell phone', 'microwave', 'oven', 'toaster', 'sink', 'refrigerator',
            'book', 'clock', 'vase', 'scissors', 'teddy bear', 'hair drier', 'toothbrush'
        ]

    def annotate_image(self, image_path: str, output_path: str, detections: Dict[str, Any]):
        """
        Annotate image with detection results

        Args:
            image_path: Input image path
            output_path: Output annotated image path
            detections: Detection results
        """
        if not self.has_cv2:
            raise Exception("OpenCV required for image annotation")

        try:
            import cv2

            # Load image
            image = cv2.imread(image_path)

            # Draw bounding boxes
            for obj in detections['detected_objects']:
                box = obj['bounding_box']
                x, y, w, h = box['x'], box['y'], box['width'], box['height']

                # Color based on category
                category = obj.get('category', 'other')
                if category == 'person':
                    color = (0, 255, 0)  # Green
                elif category == 'vehicle':
                    color = (255, 0, 0)  # Blue
                elif category == 'weapon':
                    color = (0, 0, 255)  # Red
                else:
                    color = (255, 255, 0)  # Cyan

                # Draw box
                cv2.rectangle(image, (x, y), (x + w, y + h), color, 2)

                # Draw label
                label = f"{obj['class']}: {obj['confidence']:.2f}"
                cv2.putText(image, label, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, color, 2)

            # Save annotated image
            cv2.imwrite(output_path, image)
            self.logger.info(f"Annotated image saved to: {output_path}")

        except Exception as e:
            self.logger.error(f"Image annotation error: {str(e)}")
            raise


if __name__ == "__main__":
    print("Object Detector - Advanced Object Recognition")
    print("=" * 60)

    detector = ObjectDetector()

    print("\nCapabilities:")
    print("  - YOLO object detection")
    print("  - Vehicle detection")
    print("  - Weapon detection")
    print("  - Landmark identification")
    print("  - Logo/brand recognition")
    print("\nSupported models:")
    for model, available in detector.models_available.items():
        status = "Available" if available else "Not available"
        print(f"  - {model}: {status}")
    print("\nUsage:")
    print("  results = detector.detect_objects('image.jpg')")
    print("  vehicles = detector.detect_vehicles('traffic.jpg')")
    print("  weapons = detector.detect_weapons('security_cam.jpg')")
