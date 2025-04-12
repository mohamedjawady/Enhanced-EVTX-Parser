"""
Enhanced EVTX Parser - A comprehensive tool to parse Windows XML Event Log (EVTX) files

This script provides functionality to parse EVTX files and extract event data
in various formats including JSON, XML, and CSV. Also retrieves rendered messages.
"""

import argparse
import csv
import json
import os
import sys
import xml.dom.minidom
from datetime import datetime
from typing import Dict, List, Union, Optional, Any
import subprocess

try:
    import Evtx.Evtx as evtx 
    import Evtx.Views as e_views 
except ImportError:
    print("Required dependency 'python-evtx' not found.")
    print("Please install it using: pip install python-evtx")
    sys.exit(1)

try:
    import win32evtlog
    import win32evtlogutil
    import win32con
    import winerror
    HAS_WIN32 = True
except ImportError:
    print("Warning: pywin32 not found. Message rendering will be disabled.")
    print("To enable message rendering, install: pip install pywin32")
    HAS_WIN32 = False

class EvtxParser:
    """Class for parsing and extracting data from EVTX files"""

    def __init__(self, file_path: str):
        """
        Initialize the EVTX parser

        Args:
            file_path: Path to the EVTX file
        """
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"EVTX file not found: {file_path}")

        self.message_cache = {}

    def get_record_count(self) -> int:
        """Return the total number of records in the EVTX file"""
        with evtx.Evtx(self.file_path) as evtx_file:
            return evtx_file.chunks_table.count

    def get_records(self, limit: Optional[int] = None, debug: bool = False, 
                   render_messages: bool = True) -> List[Dict[str, Any]]:
        """
        Extract records from the EVTX file

        Args:
            limit: Maximum number of records to extract (None for all)
            debug: If True, print the XML for each record for debugging
            render_messages: If True, attempt to retrieve rendered message text

        Returns:
            List of dictionaries containing event data
        """
        records = []
        count = 0

        try:
            with evtx.Evtx(self.file_path) as evtx_file:
                for record in evtx_file.records():
                    if limit is not None and count >= limit:
                        break

                    try:
                        xml_str = record.xml()

                        if debug:
                            print(f"\n--- Record {record.record_num()} XML ---")
                            print(xml_str)
                            print("-----------------------------\n")

                        event_data = self._parse_xml_to_dict(xml_str)
                        event_data['record_num'] = record.record_num()

                        if render_messages and HAS_WIN32:
                            self._add_rendered_message(event_data, debug)

                        records.append(event_data)
                        count += 1
                    except Exception as e:
                        print(f"Error parsing record {record.record_num()}: {e}", file=sys.stderr)
                        if debug:
                            import traceback
                            traceback.print_exc()
                        continue
        except Exception as e:
            print(f"Error reading EVTX file: {e}", file=sys.stderr)
            if debug:
                import traceback
                traceback.print_exc()

        return records

    def _powershell_render_message(self, record_id: int) -> Optional[str]:
        try:
            ps_cmd = f'Get-WinEvent -Path "{self.file_path}" | Where-Object {{$_.RecordId -eq {record_id}}} | Select -ExpandProperty Message'
            result = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def _powershell_render_message_by_event_id(self, event_id: Union[int, str]) -> Optional[str]:
        try:
            ps_cmd = (
                f"Get-WinEvent -Path '{self.file_path}' | "
                f"Where-Object {{$_.Id -eq {event_id}}} | "
                f"Select-Object -First 1 -ExpandProperty Message"
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception as e:
            if hasattr(self, "debug") and self.debug:
                print(f"[PowerShell Fallback Error] {e}")
        return None

    def _add_rendered_message(self, event_data: Dict[str, Any], debug: bool = False) -> None:
        """
        Add rendered message to event data using Windows message resources

        Args:
            event_data: Dictionary containing the event data
            debug: If True, print debug information
        """
        try:

            provider_name = event_data["System"]["Provider"]["Name"]
            event_id = int(event_data["System"]["EventID"]["Value"])

            qualifiers_str = event_data["System"]["EventID"]["Qualifiers"]
            qualifiers = int(qualifiers_str) if qualifiers_str else 0

            event_id_with_qualifiers = event_id | (qualifiers << 16)

            cache_key = f"{provider_name}:{event_id_with_qualifiers}"

            message = None
            if cache_key in self.message_cache:
                message = self.message_cache[cache_key]
            else:

                try:

                    source_name = provider_name

                    message = win32evtlogutil.FormatMessage(source_name, event_id_with_qualifiers)

                    if not message and event_data["System"]["Provider"]["EventSourceName"]:
                        source_name = event_data["System"]["Provider"]["EventSourceName"]
                        message = win32evtlogutil.FormatMessage(source_name, event_id_with_qualifiers)

                    if not message:
                        message = win32evtlogutil.FormatMessage(source_name, event_id)

                    self.message_cache[cache_key] = message
                except Exception as e:
                    if debug:
                        print(f"Error retrieving message for {cache_key}: {e}")

                    self.message_cache[cache_key] = None

            if message and event_data.get("EventData"):

                event_params = []
                for key, value in event_data["EventData"].items():
                    if key.startswith("Data_") and value:

                        if isinstance(value, str) and '\n' in value:
                            parts = [p for p in value.split('\n') if p]
                            event_params.extend(parts)
                        else:
                            event_params.append(value)

                for i, param in enumerate(event_params):
                    placeholder = f"%{i+1}"
                    if placeholder in message:
                        message = message.replace(placeholder, str(param))

            if message:
                event_data["RenderedMessage"] = message
            elif HAS_WIN32:

                fallback_message = self._powershell_render_message_by_event_id(event_id)
                if fallback_message:
                    event_data["RenderedMessage"] = fallback_message
                else:
                    event_data["RenderedMessage"] = "[Unavailable]"
            else:
                event_data["RenderedMessage"] = "[Unavailable]"
        except Exception as e:

            if debug:
                print(f"Message rendering error: {e}")
            pass

    def _parse_xml_to_dict(self, xml_str: str) -> Dict[str, Any]:
        """
        Parse XML string to dictionary

        Args:
            xml_str: XML string from EVTX record

        Returns:
            Dictionary with extracted event data
        """
        dom = xml.dom.minidom.parseString(xml_str)
        event = dom.getElementsByTagName("Event")[0]

        system = event.getElementsByTagName("System")[0]

        event_id_element = system.getElementsByTagName("EventID")
        event_id = ""
        qualifiers = ""
        if event_id_element:
            event_id = self._get_element_text(system, "EventID")
            qualifiers = event_id_element[0].getAttribute("Qualifiers")

        provider_element = system.getElementsByTagName("Provider")
        provider_name = ""
        provider_guid = ""
        event_source_name = ""
        if provider_element:
            provider_name = provider_element[0].getAttribute("Name")
            provider_guid = provider_element[0].getAttribute("Guid")
            event_source_name = provider_element[0].getAttribute("EventSourceName")

        result = {
            "System": {
                "Provider": {
                    "Name": provider_name,
                    "Guid": provider_guid,
                    "EventSourceName": event_source_name
                },
                "EventID": {
                    "Value": event_id,
                    "Qualifiers": qualifiers
                },
                "Version": self._get_element_text(system, "Version"),
                "Level": self._get_element_text(system, "Level"),
                "Task": self._get_element_text(system, "Task"),
                "Opcode": self._get_element_text(system, "Opcode"),
                "Keywords": self._get_element_text(system, "Keywords"),
                "TimeCreated": {
                    "SystemTime": self._get_element_attribute(system, "TimeCreated", "SystemTime")
                },
                "EventRecordID": self._get_element_text(system, "EventRecordID"),
                "Channel": self._get_element_text(system, "Channel"),
                "Computer": self._get_element_text(system, "Computer"),
            }
        }

        correlation_elements = system.getElementsByTagName("Correlation")
        if correlation_elements:
            correlation = correlation_elements[0]
            correlation_data = {}

            activity_id = correlation.getAttribute("ActivityID")
            related_activity_id = correlation.getAttribute("RelatedActivityID")

            if activity_id:
                correlation_data["ActivityID"] = activity_id
            if related_activity_id:
                correlation_data["RelatedActivityID"] = related_activity_id

            if correlation_data:
                result["System"]["Correlation"] = correlation_data
            else:
                result["System"]["Correlation"] = None
        else:
            result["System"]["Correlation"] = None

        execution_elements = system.getElementsByTagName("Execution")
        if execution_elements:
            execution = execution_elements[0]
            result["System"]["Execution"] = {
                "ProcessID": execution.getAttribute("ProcessID"),
                "ThreadID": execution.getAttribute("ThreadID")
            }
        else:
            result["System"]["Execution"] = None

        security_elements = system.getElementsByTagName("Security")
        if security_elements:
            security = security_elements[0]
            result["System"]["Security"] = {
                "UserID": security.getAttribute("UserID")
            }
        else:
            result["System"]["Security"] = None

        event_data_nodes = event.getElementsByTagName("EventData")
        if event_data_nodes:
            event_data_element = event_data_nodes[0]
            data_elements = event_data_element.getElementsByTagName("Data")

            if data_elements:

                event_data = {}
                for idx, data in enumerate(data_elements):
                    name = data.getAttribute("Name")
                    value = data.firstChild.nodeValue if data.firstChild else ""

                    if name:
                        event_data[name] = value
                    else:

                        event_data[f"Data_{idx}"] = value

                result["EventData"] = event_data
            else:

                text_content = event_data_element.textContent.strip()
                if text_content:
                    lines = [line.strip() for line in text_content.split('\n') if line.strip()]
                    result["EventData"] = {f"Data_{i}": value for i, value in enumerate(lines)}

        user_data_nodes = event.getElementsByTagName("UserData")
        if user_data_nodes:
            result["UserData"] = self._parse_user_data_node(user_data_nodes[0])

        rendering_info_nodes = event.getElementsByTagName("RenderingInfo")
        if rendering_info_nodes:
            result["RenderingInfo"] = self._parse_rendering_info(rendering_info_nodes[0])

        binary_nodes = event.getElementsByTagName("Binary")
        if binary_nodes and binary_nodes[0].firstChild:
            result["Binary"] = binary_nodes[0].firstChild.nodeValue

        return result

    def _parse_user_data_node(self, user_data_node) -> Dict[str, Any]:
        """Parse UserData node which can contain custom XML structures"""
        result = {}

        for child in user_data_node.childNodes:
            if child.nodeType == child.ELEMENT_NODE:

                element_data = {}

                for attr_name, attr_value in child.attributes.items():
                    element_data[f"@{attr_name}"] = attr_value

                for sub_child in child.childNodes:
                    if sub_child.nodeType == sub_child.ELEMENT_NODE:
                        element_data[sub_child.nodeName] = self._extract_element_content(sub_child)

                if not element_data and child.firstChild and child.firstChild.nodeType == child.TEXT_NODE:
                    result[child.nodeName] = child.firstChild.nodeValue
                else:
                    result[child.nodeName] = element_data

        return result

    def _extract_element_content(self, element) -> Any:
        """Recursively extract content from an element"""

        has_child_elements = False
        for child in element.childNodes:
            if child.nodeType == child.ELEMENT_NODE:
                has_child_elements = True
                break

        if not has_child_elements:
            return element.firstChild.nodeValue if element.firstChild else ""

        result = {}

        for attr_name, attr_value in element.attributes.items():
            result[f"@{attr_name}"] = attr_value

        for child in element.childNodes:
            if child.nodeType == child.ELEMENT_NODE:

                if child.nodeName in result:

                    if not isinstance(result[child.nodeName], list):
                        result[child.nodeName] = [result[child.nodeName]]
                    result[child.nodeName].append(self._extract_element_content(child))
                else:
                    result[child.nodeName] = self._extract_element_content(child)

        return result

    def _parse_rendering_info(self, rendering_info_node) -> Dict[str, str]:
        """Parse RenderingInfo node"""
        result = {}

        message_nodes = rendering_info_node.getElementsByTagName("Message")
        if message_nodes and message_nodes[0].firstChild:
            result["Message"] = message_nodes[0].firstChild.nodeValue

        level_nodes = rendering_info_node.getElementsByTagName("Level")
        if level_nodes and level_nodes[0].firstChild:
            result["Level"] = level_nodes[0].firstChild.nodeValue

        task_nodes = rendering_info_node.getElementsByTagName("Task")
        if task_nodes and task_nodes[0].firstChild:
            result["Task"] = task_nodes[0].firstChild.nodeValue

        opcode_nodes = rendering_info_node.getElementsByTagName("Opcode")
        if opcode_nodes and opcode_nodes[0].firstChild:
            result["Opcode"] = opcode_nodes[0].firstChild.nodeValue

        keywords_nodes = rendering_info_node.getElementsByTagName("Keywords")
        if keywords_nodes:
            keywords = []
            for keyword in keywords_nodes[0].getElementsByTagName("Keyword"):
                if keyword.firstChild:
                    keywords.append(keyword.firstChild.nodeValue)
            if keywords:
                result["Keywords"] = keywords

        channel_nodes = rendering_info_node.getElementsByTagName("Channel")
        if channel_nodes and channel_nodes[0].firstChild:
            result["Channel"] = channel_nodes[0].firstChild.nodeValue

        provider_nodes = rendering_info_node.getElementsByTagName("Provider")
        if provider_nodes and provider_nodes[0].firstChild:
            result["Provider"] = provider_nodes[0].firstChild.nodeValue

        return result

    def _get_element_text(self, parent, tag_name: str) -> str:
        """Extract text from an XML element"""
        elements = parent.getElementsByTagName(tag_name)
        if elements and elements[0].firstChild:
            return elements[0].firstChild.nodeValue
        return ""

    def _get_element_attribute(self, parent, tag_name: str, attr_name: str) -> str:
        """Extract attribute value from an XML element"""
        elements = parent.getElementsByTagName(tag_name)
        if elements:
            return elements[0].getAttribute(attr_name)
        return ""

    def export_to_json(self, output_path: str, limit: Optional[int] = None, 
                        debug: bool = False, render_messages: bool = True) -> None:
        """
        Export EVTX records to JSON file

        Args:
            output_path: Path to save the JSON output
            limit: Maximum number of records to export
            debug: If True, print the XML for each record for debugging
            render_messages: If True, attempt to retrieve rendered message text
        """
        records = self.get_records(limit, debug, render_messages)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(records, f, indent=2, default=str)

        print(f"Exported {len(records)} records to {output_path}")

    def export_to_csv(self, output_path: str, limit: Optional[int] = None, 
                      debug: bool = False, render_messages: bool = True) -> None:
        """
        Export EVTX records to CSV file

        Args:
            output_path: Path to save the CSV output
            limit: Maximum number of records to export
            debug: If True, print the XML for each record for debugging
            render_messages: If True, attempt to retrieve rendered message text
        """
        records = self.get_records(limit, debug, render_messages)
        if not records:
            print("No records found to export")
            return

        flattened_records = []
        for record in records:
            flat_record = self._flatten_dict(record)
            flattened_records.append(flat_record)

        fieldnames = set()
        for record in flattened_records:
            for key in record.keys():
                fieldnames.add(key)

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(fieldnames))
            writer.writeheader()
            writer.writerows(flattened_records)

        print(f"Exported {len(records)} records to {output_path}")

    def _flatten_dict(self, d: Dict, parent_key: str = '', sep: str = '_') -> Dict:
        """
        Flatten nested dictionaries for CSV export

        Args:
            d: Dictionary to flatten
            parent_key: Parent key for nested elements
            sep: Separator between keys

        Returns:
            Flattened dictionary
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k

            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep).items())
            elif isinstance(v, list):

                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, v))

        return dict(items)

    def export_to_xml(self, output_path: str, limit: Optional[int] = None, 
                      debug: bool = False, render_messages: bool = True) -> None:
        """
        Export EVTX records to XML file

        Args:
            output_path: Path to save the XML output
            limit: Maximum number of records to export
            debug: If True, print the XML for each record for debugging
            render_messages: If True, attempt to retrieve rendered message text
        """

        if render_messages and HAS_WIN32:
            records = self.get_records(limit, debug, render_messages)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write('<Events>\n')

                for record in records:

                    try:

                        f.write(f'<Event RecordID="{record["record_num"]}">\n')

                        if "RenderedMessage" in record:
                            f.write(f'  <RenderedMessage>{record["RenderedMessage"]}</RenderedMessage>\n')

                        for key, value in record.items():
                            if key not in ["record_num", "RenderedMessage"]:
                                f.write(f'  <{key}>')
                                f.write(json.dumps(value))
                                f.write(f'</{key}>\n')

                        f.write('</Event>\n')
                    except Exception as e:
                        print(f"Error processing record {record['record_num']}: {e}", file=sys.stderr)

                f.write('</Events>')
        else:

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write('<Events>\n')

                count = 0
                with evtx.Evtx(self.file_path) as evtx_file:
                    for record in evtx_file.records():
                        if limit is not None and count >= limit:
                            break

                        try:
                            xml_str = record.xml()

                            if debug:
                                print(f"\n--- Record {record.record_num()} XML ---")
                                print(xml_str)
                                print("-----------------------------\n")

                            f.write(xml_str)
                            f.write('\n')
                            count += 1
                        except Exception as e:
                            print(f"Error processing record {record.record_num()}: {e}", file=sys.stderr)

                f.write('</Events>')

        print(f"Exported records to {output_path}")

def main():
    """Main function to run the EVTX parser from command line"""
    parser = argparse.ArgumentParser(description="Parse and extract data from Windows EVTX files")
    parser.add_argument("file", help="Path to the EVTX file")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["json", "csv", "xml"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("-l", "--limit", type=int, help="Limit the number of records to process")
    parser.add_argument("-c", "--count", action="store_true", help="Only show the record count")
    parser.add_argument("-d", "--debug", action="store_true", help="Print XML content for debugging")
    parser.add_argument("-p", "--pretty", action="store_true", help="Pretty-print JSON output")
    parser.add_argument("-r", "--render-messages", action="store_true", default=True,
                        help="Attempt to retrieve rendered message text (requires pywin32)")
    parser.add_argument("--no-render", action="store_false", dest="render_messages",
                        help="Disable message rendering")

    args = parser.parse_args()

    try:
        evtx_parser = EvtxParser(args.file)

        if args.count:
            count = evtx_parser.get_record_count()
            print(f"Total records in {args.file}: {count}")
            return

        if not args.output:
            base_name = os.path.splitext(os.path.basename(args.file))[0]
            args.output = f"{base_name}.{args.format}"

        if args.format == "json":
            evtx_parser.export_to_json(args.output, args.limit, args.debug, args.render_messages)

            if args.pretty and os.path.exists(args.output):
                with open(args.output, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=4, default=str)

        elif args.format == "csv":
            evtx_parser.export_to_csv(args.output, args.limit, args.debug, args.render_messages)
        elif args.format == "xml":
            evtx_parser.export_to_xml(args.output, args.limit, args.debug, args.render_messages)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()