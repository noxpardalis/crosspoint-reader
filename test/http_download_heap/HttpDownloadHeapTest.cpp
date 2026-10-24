#include <gtest/gtest.h>

#include "network/HttpDownloader.h"

TEST(HttpDownloadHeap, PlainHttpDoesNotNeedTlsHeadroom) {
  EXPECT_TRUE(HttpDownloader::hasDownloadHeapHeadroom("http://10.0.0.2/book.epub", 1, 1));
}

TEST(HttpDownloadHeap, HttpsNeedsBothHeapFloors) {
  EXPECT_FALSE(HttpDownloader::hasDownloadHeapHeadroom(
      "https://books.example/book.epub", HttpDownloader::MIN_TLS_FREE_HEAP - 1, HttpDownloader::MIN_TLS_MAX_ALLOC));
  EXPECT_FALSE(HttpDownloader::hasDownloadHeapHeadroom(
      "https://books.example/book.epub", HttpDownloader::MIN_TLS_FREE_HEAP, HttpDownloader::MIN_TLS_MAX_ALLOC - 1));
  EXPECT_TRUE(HttpDownloader::hasDownloadHeapHeadroom(
      "https://books.example/book.epub", HttpDownloader::MIN_TLS_FREE_HEAP, HttpDownloader::MIN_TLS_MAX_ALLOC));
}

TEST(HttpDownloadHeap, RedirectedPlainHttpKeepsConservativeFloor) {
  EXPECT_FALSE(HttpDownloader::hasDownloadHeapHeadroom("http://10.0.0.2/book.epub", 1, 1, false));
  EXPECT_TRUE(HttpDownloader::hasDownloadHeapHeadroom("http://10.0.0.2/book.epub", HttpDownloader::MIN_TLS_FREE_HEAP,
                                                      HttpDownloader::MIN_TLS_MAX_ALLOC, false));
}
