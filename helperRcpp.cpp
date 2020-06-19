#include <Rcpp.h>
using namespace Rcpp;

// [[Rcpp::export]]
void findChords(DataFrame &df, int length) {
  CharacterVector dips = df["DIP"];
  for(int i = 0; i < length; ++i) {
    Rcout << dips[i] << "\n";
  }
}
