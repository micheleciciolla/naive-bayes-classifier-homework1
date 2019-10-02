% MALWARE DETECTOR using NAIVE BAYES
clc
close all
clear

addpath('test_50','dataset_1420');

% dataset is composed by 500 elements
% divided in k = 20 slots. We give 20 slots to train and 5 to test
% for out k-cross validation
k_train = 400; % k1
k_test = 100; % k2


%--------------------------------------------------------------------------
load('dictionary.mat');
% estraggo la prima colonna del dictionary fornito
dictionary_column = dictionary(:,1);
% trasformo da matrice ad array
dictionary_column = table2array(dictionary_column);
% converto gli elementi in stringhe
dictionary_column = cellstr(dictionary_column);
dictionary_column = string(dictionary_column);
%--------------------------------------------------------------------------


%--------------------------------------------------------------------------
% MANIPOLAZIONE VETTORE DEl DATASET

filePattern = fullfile('./dataset_1420//','');
files = dir(filePattern);
files2 = struct('name', {files(1:k_train).name});
files2(1:2) = [];
dataset = table({files2.name}.', 'VariableNames', {'name'});

% estraggo la prima colonna
dataset = dataset(:,1);
% trasformo da matrice ad array
dataset = table2array(dataset);
% converto gli elementi in stringhe
dataset = cellstr(dataset); dataset = string(dataset);
%--------------------------------------------------------------------------

% calculating n° and prob of malwares in dataset
[n_mal,malware_index] = malware_count(dictionary_column,dataset);
% here i'm removing 0 from vector
malware_index = malware_index(malware_index~= 0);
malware_index = sort(malware_index);

p_mal = n_mal / length(dataset);


% X = { word1, word2, word3, word4 }

word1 = "call::sendSMS";
word2 = "getSubscriberId";
word4 = "permission::android.permission.SEND_SMS";
word3 = "intent::android.intent.action.USER_PRESENT";

% plausible words
% sendTextMessage
% system/bin/su
% getSubscriberId
% lebar.gicp.net


pw1_y = mal_probability(word1, dataset, malware_index);
pw1_n = non_mal_probability(word1, dataset, malware_index);

pw2_y = mal_probability(word2, dataset, malware_index);
pw2_n = non_mal_probability(word2, dataset, malware_index);

pw3_y = mal_probability(word3, dataset, malware_index);
pw3_n = non_mal_probability(word3, dataset, malware_index);

pw4_y = mal_probability(word4, dataset, malware_index);
pw4_n = non_mal_probability(word4, dataset, malware_index);


%%%%%%%%%%%%%%%%%%%%%%%% TEST SECTION %%%%%%%%%%%%%%%%%%%%%%%%%%

%--------------------------------------------------------------------------
% MANIPOLAZIONE VETTORE TEST_SET
filePattern1 = fullfile('./test_50/////','');
filess = dir(filePattern1);
files22 = struct('name', {filess(1:k_test).name});
files22(1:2) = [];
test = table({files22.name}.', 'VariableNames', {'name'});

% estraggo la prima colonna
test = test(:,1);
% trasformo da matrice ad array
test = table2array(test);
% converto gli elementi in stringhe
test = cellstr(test); 
test = string(test);

% calcola la presenza di malware nel test
[n_mal_test,malware_index_test] = malware_count (dictionary_column,test);
malware_index_test = malware_index_test(malware_index_test~= 0);
% malware_index_test = sort(malware_index_test);

detections = 0;
for t=1:length(test)
    
    new_fileID = fopen(test(t));
    new_elem = textscan(new_fileID, '%s');
    new_elem = cellstr(new_elem{1,1}); 
    new_elem = string(new_elem);
        
    % output of classication is 0,1
    classification = naive_bayes(word1,pw1_y,pw1_n,word2,pw2_y,pw2_n, word3,pw3_y,pw3_n,word4,pw4_y,pw4_n,new_elem);
    
    detections = detections + classification;
    
    fclose(new_fileID);
end


performance = (detections / n_mal_test)

% controllo se ciò che ho trovato è effettivamente un malware a mano
% confrontando il codice hash dei presunti malware con il dizionario 

% END MAIN






%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
function [num,ml_indexes] = malware_count(dictionary_column,set)
num=0;
% creating an empty vector
ml_indexes = [];
for i=2:length(dictionary_column)
    for j=1:length(set)
        if strcmp(dictionary_column(i,1), set(j,1)) == 1
            num = num +1;
            % devi salvare gli indici dei malware nel set in un array
            ml_indexes(j) = j;
            
        end
    end
    
end

end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
function [prob] =  mal_probability(word, dataset, ml_indexes)
% probability and occurrency of WORD inside a malware file

prob = 0;
occ = 0;

for i=1:length(ml_indexes)
    
    % create an id for each dataset file opened
    dataset_elem_id = fopen(dataset(i));
    % convert each file as an array of string
    dataset_elem = textscan(dataset_elem_id, '%s');
    dataset_elem = cellstr(dataset_elem{1,1}); 
    dataset_elem = string(dataset_elem);
    
    % notfound is used to be sure to count just 1 words per file 
    notfound = true;
    
    for j=1:length(dataset_elem)
        
        % se una parte del testo coincide con "call::getDeviceId" aumenta
        % il contatore
        
        if contains(dataset_elem(j),word) && notfound
            occ = occ + 1;
            notfound = false; % this mean we already found word
        end
    end
    fclose(dataset_elem_id);
end

prob = occ / length(ml_indexes);

% we model 0 probability with 1%
if (prob == 0)
    prob = 0.01;
end

end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
function [prob_word] =  non_mal_probability(word, dataset, malware_index)

prob_word = 0;
occ = 0;

for i=1:length(dataset)
    
    % malware index is sorted [12,43,66,..]
    if belongs(i,malware_index)
        % if index belongs to malware index, skip element cause we need to
        % check only non-malware items.
        i=i+1;
    end
    
    % create an id for each dataset file opened
    id = fopen(dataset(i));
    % convert each file as an array of string
    current_elem = textscan(id, '%s');
    current_elem = cellstr(current_elem{1,1}); 
    current_elem = string(current_elem);
    
    not_found = true;
    
    for j=1:length(current_elem)
        if (contains(current_elem(j),word) && not_found)
            occ = occ + 1;
            not_found = false;
        end
        
        fclose(id);
    end

D = length(dataset) - length(malware_index);
prob_word = occ / D  ;

if (prob_word == 0)
    prob_word = 0.01;
end
end

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% calculate naive bayes value using 4 words
function [res] = naive_bayes(word1, pw1_y, pw1_n, word2, pw2_y, pw2_n, word3, pw3_y, pw3_n, word4, pw4_y, pw4_n, elem )
    
% QUESTA FUNZIONE CALCOLA IL VALORE RESTITUITO DAL NAIVE BAYES CLASSIFIER

words_inside = 0; % just to check how many words are founded inside each sample

% N.B
% we model the absence of word with prob=1, it's not correct,we know, but
% it makes less damages in the calculus. 

if is_inside(word1,elem)==false
    pw1_y = 1; pw1_n= 1;
    
else words_inside = words_inside +1;
end

if is_inside(word2,elem)==false
    pw2_y = 1; pw2_n= 1;
    
else words_inside = words_inside +1;
end

if is_inside(word3,elem)==false
    pw3_y = 1; pw3_n= 1;
    
else words_inside = words_inside +1;
end

if is_inside(word4,elem)==false
    pw4_y = 1; pw4_n= 1;
    
else words_inside = words_inside +1;
end

yes = pw1_y * pw2_y * pw3_y * pw4_y*0.05;
no =  pw1_n * pw2_n * pw3_n * pw4_n*0.95;
res = argmax(yes,no);

disp(words_inside);
end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% return true if a word exists in an element of dataset
function [res] = is_inside(word,elem)
res=false;
for i=1:length(elem)
    if strcmp(elem(i),word)
        res=true;
    end
end
end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% argmax function between two numbers
function [res] = argmax(yes,no)
res = 0;
if yes >= no
    res = 1;
end
end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% se l' indice è presente nel set di indici "set" ritorna true
function [res] = belongs(index,set)
res=false;
for i=1:length(set)
    if set(i) == index
        res=true;
    end
end
end