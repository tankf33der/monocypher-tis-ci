// PicoLisp tis.config file generator

(setq
   *M
   '("x86_16" "x86_huge" "x86_32" "x86_64")
   *F
   '("p1305" "blake2b") )


(out "tis.json"
   (for F *F
      (for M *M
         (prinl "{")
         (println F M)
         (prinl "}")
      )
   )
)

(bye)
