import json
import logging  # import python logging module
import os
import sys
import time

import logging_config as logger  # import custom logging format
import maxminddb
import numpy as np
import pandas as pd
import SubnetTree


class FileHandler(object):
    """
    Contains methods to manage pmacct Ntflow csv files.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.directory_to_monitor = os.environ["RAW_DATA"]
        self.dest_folder = os.environ["TO_SPLUNK"]
        self.internet_folder = os.environ["CSV_ENRICHMENT_DATA"]
        self.json_file = os.environ["JSON_FILE"]

    def get_latest_filename(self):
        """
        Obtains the latest csv pmacct file by time.
        :return: latest file name
        """

        # Get the latest filename from netflow directory by time
        while True:
            try:
                list_of_filenames = os.listdir(self.directory_to_monitor)
                paths = [
                    os.path.join(self.directory_to_monitor, basename)
                    for basename in list_of_filenames
                ]
                latest_file = max(paths, key=os.path.getctime)
                self.logger.info("The latest file is {}".format(latest_file))
            except ValueError:
                self.logger.info(
                    "{} directory is empty. Sleep for 2 sec and check again".format(
                        self.directory_to_monitor
                    )
                )
                time.sleep(2)
                current_dir = os.getcwd()

                #  If there are no more files in raw folder and running in the dev mode, then exit.
                if "_dev" in str(current_dir):
                    self.logger.info("Exiting, because running in the dev directory")
                    sys.exit()

            else:
                # Obtain file extension and make sure it is csv
                file_string_parts = latest_file.split(".")
                file_extension = file_string_parts[
                    -1
                ]  # the last element in the list is the file extension
                if file_extension == "csv":
                    self.logger.info("{} file extension is csv.".format(latest_file))
                    return latest_file
                else:
                    self.logger.error(
                        "{} file has wrong extension. Only csv is accepted. Sleep for 2 sec and check again".format(
                            latest_file
                        )
                    )
                    time.sleep(2)

    def check_file_size(self):
        """
        Check is the latest file size compared to the size after 2 s is the same.
        This ensures that writing to a file is complete
        :return:
        """
        file_v1 = self.get_latest_filename()
        file_v1_details = os.stat(file_v1)  # initial file details
        file_v1_size = file_v1_details.st_size  # initial file size
        time.sleep(2)
        file_v2_details = os.stat(file_v1)  # file details 2 sec later
        file_v2_size = file_v2_details.st_size  # file size 2 sec later
        if file_v1_size == file_v2_size:
            self.logger.info(
                "{} file size is the same as 2 sec ago. Returning filename".format(
                    file_v1
                )
            )
            return file_v1
        else:
            self.logger.info(
                "{} file size is different compared to 2 sec ago. Checking again".format(
                    file_v1
                )
            )
            return self.check_file_size()


class NetflowEnrichment(FileHandler):
    """
    Contains methods to enrich the data from pmacct csv files with the data from the IceCube
    """

    def __init__(self):
        FileHandler.__init__(self)
        self.netflow_file = FileHandler.check_file_size(self)
        self.fields = self.read_json_file()
        self.custom_fields = [
            "product_ip",
            "client_ip",
            "isp_int",
            "client_bgp_as",
            "Country",
            "Country_code",
            "City",
        ]
        self.GeoLite2_City_file = "/data/splunk/share/GeoLite2-City.mmdb"

    def read_json_file(self):
        """
        Read fields.json file which defines netflow fields to be enriched.
        :return: json data structure
        """
        try:
            with open(self.json_file) as json_file:
                return json.load(json_file)
        except json.decoder.JSONDecodeError as e:
            self.logger.error(
                "JSON formatting error in fields.json file : {}".format(e)
            )
            sys.exit()
        except FileNotFoundError as e:
            self.logger.error("fields.json file not found: {}.".format(e))
            sys.exit()

    def replace_headers(self):
        """
        Load latest pmacct netflow file to a pandas dataframe.
        Rename the header according to 'pmacct' in fileds.json.
        :return: pandas dataframe with renamed header
        """

        # Read latest pmacct netflow csv file to a pandas dataframe
        try:
            file_df = pd.read_csv(self.netflow_file)
        except (pd.errors.ParserError, pd.errors.EmptyDataError) as parse_error:
            self.logger.error(
                "Error parsing {} file with pandas. {}".format(
                    self.netflow_file, parse_error
                )
            )
            sys.exit()

        try:
            self.logger.info(
                "Renaming dataframe headers ad per 'pmacct' dict from fields.json"
            )
            file_df.rename(columns=self.fields["netflow_orbit"]["pmacct"], inplace=True)
        except KeyError as e:
            self.logger.error("Error reading fields.json. {} key not found".format(e))
            sys.exit()
        return file_df

    def cidr_lookup(self, file_df, enrichment_df, match_fields):
        t = SubnetTree.SubnetTree()
        include_fields = list(enrichment_df.columns)[0]

        for ip_range in enrichment_df[include_fields].tolist():
            t[ip_range] = str(ip_range)

        def ip_lookup(ip):
            if ip in t:
                return t[ip]

        file_df[include_fields] = file_df[match_fields[0]].apply(lambda x: ip_lookup(x))

        file_df = file_df.merge(enrichment_df, on=include_fields, how="left")
        return file_df

    def left_join_lookup(self, file_df, enrichment_df, match_fields):
        file_df = file_df.merge(enrichment_df, on=match_fields, how="left")
        return file_df

    def geo_lookup(self, file_df):
        reader = maxminddb.open_database(self.GeoLite2_City_file, maxminddb.MODE_MMAP)
        ip_cashe = dict()

        def single_ip_lookup(ip):
            try:
                geo_list = ip_cashe[ip]
                return geo_list
            except KeyError:
                try:
                    response = reader.get(ip)
                except:
                    ip_cashe[ip] = [None, None, None]
                    return [None, None, None]
                try:
                    country_name = response["country"]["names"]["en"]
                except:
                    country_name = None
                    pass
                try:
                    country_code = response["country"]["iso_code"]
                except:
                    country_code = None
                    pass
                try:
                    city = response["city"]["names"]["en"]
                except:
                    city = None
                    pass
                finally:
                    geo_list = [country_name, country_code, city]
                    ip_cashe[ip] = geo_list
                    return geo_list

        file_df["Country"] = file_df["client_ip"].apply(
            lambda x: single_ip_lookup(x)[0]
        )
        file_df["Country_code"] = file_df["client_ip"].apply(
            lambda x: single_ip_lookup(x)[1]
        )
        file_df["City"] = file_df["client_ip"].apply(lambda x: single_ip_lookup(x)[2])

        return file_df

    def enrich_data(self):
        """
        Read csv files from IceCube as defined in fields.json and left merge them to 'pmacct' dataframe.
        :return: a dataframe after all csv files are merged
        """
        #   Rename the header according to 'pmacct' in fileds.json.
        file_df = self.replace_headers()

        #  Add custom fields. Also update self.custom_fields in __init__
        file_df["isp_int"] = np.where(
            file_df["flow_dir"] == 0, file_df["in_int"], file_df["out_int"]
        )
        file_df["client_bgp_as"] = np.where(
            file_df["flow_dir"] == 0, file_df["src_bgp_as"], file_df["dest_bgp_as"]
        )

        # From fields.json obtain all names of enrichment tasks.
        # 'csv' file is then created by appending '.csv' to each enrichment task.
        try:
            enrichments_tasks = self.fields["netflow_orbit"]["enrichment"]
        except KeyError as e:
            self.logger.error("Error reading fields.json. {} key not found".format(e))
            sys.exit()

        # read and merge each csv file into file_df datafrme
        for task in enrichments_tasks:
            self.logger.info("Start working on {} enrichment".format(task))
            enrichment_filename = self.fields["netflow_orbit"]["enrichment"][task][
                "filename"
            ]
            try:
                match_fields = self.fields["netflow_orbit"]["enrichment"][task][
                    "match_fields"
                ]
                rename_fields = self.fields["netflow_orbit"]["enrichment"][task][
                    "rename_fields"
                ]
                lookup_type = self.fields["netflow_orbit"]["enrichment"][task][
                    "lookup_type"
                ]
            except KeyError as e:
                self.logger.error(
                    "Error reading fields.json for {}. {} key not found".format(task, e)
                )
                sys.exit()
            try:
                enrichment_df = pd.read_csv(
                    self.internet_folder + "/" + enrichment_filename
                )
                enrichment_df = enrichment_df.replace({r"\\n": ""}, regex=True)
                enrichment_df = enrichment_df.replace({r"\\r": ""}, regex=True)
            except (pd.errors.ParserError, pd.errors.EmptyDataError) as parse_error:
                self.logger.error(
                    "Error parsing {} file with pandas. {}".format(
                        self.netflow_file, parse_error
                    )
                )
                sys.exit()

            # Rename fields so they match 'pmacct' dictionary otherwise there is no common field to be merged
            if rename_fields:
                self.logger.info("Renaming headers in {}".format(enrichment_filename))
                enrichment_df.rename(columns=rename_fields, inplace=True)

            # Check if lookup type is or 'left_join'
            self.logger.info(
                "Performing {} lookup on {} from netflow and {} file".format(
                    lookup_type, match_fields, enrichment_filename
                )
            )
            if lookup_type == "cidr":
                file_df = self.cidr_lookup(file_df, enrichment_df, match_fields)
            elif lookup_type == "left_join":
                try:
                    file_df = self.left_join_lookup(
                        file_df, enrichment_df, match_fields
                    )
                except KeyError as parse_error:
                    self.logger.error(
                        "Error merging dataframes with pandas pandas due to headers not match. The "
                        "offending field is {}".format(parse_error)
                    )
                    sys.exit()
            else:
                self.logger.error("Unknown lookup type: {}".format(lookup_type))
                sys.exit()

            self.logger.info(
                "The merged dataframe is of the following shape: {}".format(
                    file_df.shape
                )
            )

            # The product_ip and client_ip custom fields use dvc_ip-isp-raw use isp_interface field from 'dvc_ip-isp-raw'
            # therefore they can only be obtained after merging dvc_ip-isp-raw.csv file.
            if task == "dvc_ip-isp-raw":
                #  Add custom fields. Also update self.custom_fields in __init__
                file_df["product_ip"] = np.where(
                    (file_df["flow_dir"] == 0) & (file_df["isp_interface"] == "True"),
                    file_df["dest_ip"],
                    file_df["src_ip"],
                )
                file_df["client_ip"] = np.where(
                    (file_df["flow_dir"] == 0) & (file_df["isp_interface"] == "True"),
                    file_df["src_ip"],
                    file_df["dest_ip"],
                )
                file_df["product_ip"] = np.where(
                    (file_df["flow_dir"] == 1) & (file_df["isp_interface"] == "False"),
                    file_df["dest_ip"],
                    file_df["src_ip"],
                )
                file_df["client_ip"] = np.where(
                    (file_df["flow_dir"] == 1) & (file_df["isp_interface"] == "False"),
                    file_df["src_ip"],
                    file_df["dest_ip"],
                )
                self.logger.info(
                    "The netflow dataframe is of the following shape: {}".format(
                        file_df.shape
                    )
                )

        self.logger.info("Performing geolookups")
        file_df_geo = self.geo_lookup(file_df)
        self.logger.info(
            "The dataframe after geolookups is of the following shape: {}".format(
                file_df.shape
            )
        )

        return file_df_geo

    def filter_fields(self):
        """
        Filters merged datafrme to only include columns defined in fields.json 'pmacct' and 'include_fields'.
        :return: Dataframe with columns defined in fields.json
        """
        file_df = self.enrich_data()

        #  Get pmacct_fields
        pmacct_fields = list(self.fields["netflow_orbit"]["pmacct"].values())
        enrichments_tasks = self.fields["netflow_orbit"]["enrichment"]

        #  Add include_fields to pmacct_fields
        for task in enrichments_tasks:
            try:
                include_fields = self.fields["netflow_orbit"]["enrichment"][task][
                    "include_fields"
                ]
                pmacct_fields = pmacct_fields + list(include_fields)
            except KeyError as e:
                self.logger.error(
                    "Error reading fields.json for {}. {} key not found".format(task, e)
                )
                sys.exit()

        #  Add  custom_fields  to  pmacct_fields
        pmacct_fields = set(pmacct_fields + list(self.custom_fields))

        try:
            file_df = file_df[pmacct_fields]
        except KeyError as e:
            self.logger.error(
                "Filtering fileds from final merged dataframe error. Check if 'pmacct' and "
                "'include_fields' are defined correctly in fields.json {}".format(e)
            )
            sys.exit()
        return file_df

    def create_enriched_file(self):
        """
        Save merged and filtered dataframe to a csv file for Splunk indexing.
        Use the name of the oginal file when saving.
        Remove the original pmacct file.
        """
        enr_df = self.filter_fields()

        #  Obtain filename from the path
        filename = os.path.basename(self.netflow_file)
        self.logger.info("Saving enriched {} to {}".format(filename, self.dest_folder))

        #  Create a new csv file
        enr_df.to_csv(self.dest_folder + "/" + filename, index=False)
        self.logger.info("Removing {}".format(self.netflow_file))

        #  Remove original csv file
        os.remove(self.netflow_file)


if __name__ == "__main__":

    logger.start_logging("netflow_data_enrichment")
    SCRIPT_NAME = os.path.basename(__file__)
    logging.info("Start script %s ", SCRIPT_NAME)

    while True:
        enr = NetflowEnrichment()
        enr.create_enriched_file()
