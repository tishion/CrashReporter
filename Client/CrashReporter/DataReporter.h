#pragma once
#include <memory>
#include <string>

#include "CrashData.h"
#include "IDataReporter.h"

namespace CrashReporter {
/// <summary>
/// Represents the crash reporter class.
/// </summary>
class DataReporter : public IDataReporter
{
public:
  /// <summary>
  /// Constructor.
  /// </summary>
  DataReporter();

  /// <summary>
  /// Destructor.
  /// </summary>
  ~DataReporter();

  /// <summary>
  /// Reports the data.
  /// </summary>
  /// <param name="cmdLine">The crash log data.</param>
  virtual bool Report(CrashLogData& logData) override;

protected:
  /// <summary>
  /// Reports the basic log data.
  /// </summary>
  /// <param name="logData">Crash log data.</param>
  /// <param name="detailData">Crash detail data.</param>
  /// <param name="uploadToken">Upload token.</param>
  /// <returns>True if successful; otherwise false.</returns>
  bool ReportCrashLog(CrashLogData& logData, std::wstring& uploadToken);

  /// <summary>
  /// Uploads the detail data.
  /// </summary>
  /// <param name="detailData">Crash detail data.</param>
  /// <param name="uploadToken">Upload token.</param>
  /// <returns>True if successful; otherwise false.</returns>
  bool UploadCrashData(CrashDetailData& detailData,
                       const std::wstring& uploadToken);

  /// <summary>
  /// Sends the HTTP request.
  /// </summary>
  /// <param name="request">HTTP request.</param>
  /// <returns>The task with the JSON result.</returns>
  // pplx::task<web::json::value> SendHttpRequest(web::http::http_request&
  // request);

private:
  /// <summary>
  /// HTTP client.
  /// </summary>
  // std::shared_ptr<web::http::client::http_client> m_httpClient;
};
}
