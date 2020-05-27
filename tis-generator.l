// PicoLisp tis.config file generator

(setq
   *M
   (quote
      "x86_16" "x86_huge" "x86_32" "x86_64" )
   *F
   (quote
      "p1305" "blake2b" )
   *L
   (make
      (for F *F
         (for M *M
            (link (cons F M)) ) ) ) )
(out "tis.config"
   (prinl "// Auto genetated file")
   (prinl "[")
   (for (L *L L (cdr L))
      (let (F (caar L)  M (cdar L))
         (prinl "{")
         (prinl "\"name\":" (pack "\"" F " - " M "\"") ",")
         (prinl "\"files\":\"all\",")
         (prinl "\"main\":\"" F "\"")
         (prin "}")
         (and (cdr L) (prinl ",")) ) )
   (prinl "]") )
(bye)
