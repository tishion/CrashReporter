#include <atlstr.h>

#ifdef USE_CPPREST_SDK
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#endif // USE_CPPREST_SDK

#include "Constants.h"
#include "DataReporter.h"
#include "Log.h"

#ifdef USE_CPPREST_SDK
pplx::task<web::json::value>
SendHttpRequest(web::http::client::http_client& client,
                web::http::http_request& request)
{
  // Send HTTP request asynchronously
  return client.request(request).then([](web::http::http_response response) {
    web::json::value result;
    // Check the status code
    if (response.status_code() == web::http::status_codes::OK) {
      // Extract the JSON data asynchronously
      result = response.extract_json().get();
      result[U(PROPERTY_SUCCESS)] = web::json::value::boolean(true);
    } else
      result[U(PROPERTY_SUCCESS)] = web::json::value::boolean(false);

    // If failed then return an empty JSON value
    return pplx::task_from_result(result);
  });
}
#endif // USE_CPPREST_SDK

namespace CrashReporter {
DataReporter::DataReporter() {}

DataReporter::~DataReporter()
{
  // Destroy the HTTP client
  // m_httpClient.reset();
}

bool
DataReporter::Report(CrashLogData& logData)
{
  // Report the basic crash log data
  std::wstring uploadToken;
  if (!ReportCrashLog(logData, uploadToken)) {
    // Log
    LogError("Failed to report the crash log data");
    return false;
  }

  // Check if we need to upload dump file
  if (uploadToken.empty()) {
    // Log
    LogInfo("No need to upload the dump file");
    return false;
  }

  // Upload the detail data
  if (!UploadCrashData(logData.Detail, uploadToken)) {
    // Log
    LogInfo("Failed to upload the dump file");
    return false;
  }

  return true;
}

bool
DataReporter::ReportCrashLog(CrashLogData& logData, std::wstring& uploadToken)
{
  // Result
  bool result = false;

#ifdef USE_CPPREST_SDK
  // Build the URI
  web::http::uri_builder builder;
  builder.set_path(U(REPORT_PATH));
  LogInfo("Reporting URI: " << builder.to_string());

  // Build the detail data object
  web::json::value jsonDetailData;
  jsonDetailData[U(PROPERTY_SIGNATURE)] =
    web::json::value(::CA2W(logData.Detail.CrashSignature.c_str()));
  jsonDetailData[U(PROPERTY_PRODUCT_NAME)] =
    web::json::value(::CA2W(logData.Detail.ProductName.c_str()));
  jsonDetailData[U(PROPERTY_PRODUCT_VERSION)] =
    web::json::value(::CA2W(logData.Detail.ProductVersion.c_str()));
  jsonDetailData[U(PROPERTY_APPLICATIONNAME)] =
    web::json::value(::CA2W(logData.Detail.ApplicationName.c_str()));
  jsonDetailData[U(PROPERTY_EXCEPTIONADDRESS)] =
    web::json::value(::CA2W(logData.Detail.CrashAddress.c_str()));
  jsonDetailData[U(PROPERTY_EXCEPTIONMODULE)] =
    web::json::value(::CA2W(logData.Detail.CrashModule.c_str()));
  jsonDetailData[U(PROPERTY_OS_VERSION)] =
    web::json::value(::CA2W(logData.Detail.OSVersion.c_str()));
  jsonDetailData[U(PROPERTY_CALLSTACK)] =
    web::json::value(::CA2W(logData.Detail.CallStack.c_str()));

  // Build the log data object
  web::json::value jsonLogData;
  jsonLogData[U(PROPERTY_SIGNATURE)] =
    web::json::value(::CA2W(logData.Detail.CrashSignature.c_str()));
  jsonLogData[U(PROPERTY_IPADDRESS)] =
    web::json::value(::CA2W(logData.IPAddress.c_str()));
  jsonLogData[U(PROPERTY_MACHINEID)] =
    web::json::value(logData.MachineId.c_str());
  jsonLogData[U(PROPERTY_DETAIL)] = jsonDetailData;

  // Build the payload object
  web::json::value payLoad;
  payLoad[U(PROPERTY_REPORTLOG)] = jsonLogData;

  // Generate post request
  web::http::http_request request;
  request.set_request_uri(builder.to_uri());
  request.set_method(web::http::methods::POST);
  request.set_body(payLoad);

  // Create the task of sending HTTP request
  web::http::client::http_client client(U(BASE_URI));
  auto t = SendHttpRequest(client, request)
             .then([&uploadToken](web::json::value jsonValue) {
               if (jsonValue.has_field(U(PROPERTY_SUCCESS)) &&
                   jsonValue[U(PROPERTY_SUCCESS)].as_bool()) {
                 // Check whether the server require of uploading the dump file
                 if (jsonValue.has_field(U(PROPERTY_UPLOADTOKEN))) {
                   uploadToken = jsonValue[U(PROPERTY_UPLOADTOKEN)].as_string();
                   LogInfo("Upload token is " << uploadToken);
                 } else
                   LogInfo("Upload token is empty");

                 return true;
               }

               // Request was failed
               LogInfo("Report failed");
               return true;
             });

  // Try to wait for the task
  try {
    // Wait to get the result of the HTTP request
    result = t.get();
  } catch (const std::exception& e) {
    // The task failed with an exception, log it and return false
    LogError("Failed to send HTTP request, URI: "
             << request.request_uri().to_string() << " error: " << e.what());
    result = false;
  }
#endif // USE_CPPREST_SDK

  // Report success
  return result;
}

bool
DataReporter::UploadCrashData(CrashDetailData& detailData,
                              const std::wstring& uploadToken)
{
  // Result
  bool result = false;

#ifdef USE_CPPREST_SDK
  // Get file name
  std::wstring fileName = ::PathFindFileNameW(detailData.FilePath.c_str());

  // Build upload url
  web::http::uri_builder builder;
  builder.set_path(U(UPLOAD_PATH));
  builder.append_query(U(PROPERTY_UPLOADTOKEN), uploadToken);
  builder.append_query(U(PROPERTY_FILENAME), fileName);
  LogInfo("Reporting URI: " << builder.to_string());

  // Generate post request
  web::http::http_request request(web::http::methods::POST);
  request.set_request_uri(builder.to_uri());

  // Create file stream
  auto t =
    Concurrency::streams::fstream::open_istream(detailData.FilePath.c_str())
      .then([&request](Concurrency::streams::istream inputFileStream) {
        // Set file stream
        request.set_body(inputFileStream);
        return request;
      })
      .then([](web::http::http_request req) {
        // Send HTTP request
        web::http::client::http_client client(U(BASE_URI));
        auto jsonValue = SendHttpRequest(client, req).get();

        // Check the result of the response
        if (jsonValue.has_field(U(PROPERTY_SUCCESS)) &&
            jsonValue[U(PROPERTY_SUCCESS)].as_bool()) {
          LogInfo("Response result is true");
          return true;
        } else
          LogInfo("Response result is false");

        // Request is failed
        return false;
      });

  // Try to wait the task
  try {
    // Wait to get the result of the HTTP request
    result = t.get();
  } catch (const std::exception& e) {
    // Task is failed with an exception, log it and return false
    LogError("Failed to send HTTP request, URI: "
             << request.request_uri().to_string() << " error: " << e.what());
    result = false;
  }
#endif // USE_CPPREST_SDK

  return result;
}
}
